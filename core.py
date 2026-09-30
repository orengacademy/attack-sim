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
import socket
import platform
import ipaddress
import subprocess
from datetime import datetime

# ---------------------------------------------------------------------
# Configuration. Non-secret defaults (domain/user) live here; the PASSWORD is
# never hard-coded in source — it comes from the environment or a git-ignored
# credentials file, so no secret is committed. Precedence:
#   1. env vars  HARNESS_DOMAIN / HARNESS_DC_USER / HARNESS_DC_PASS
#   2. a git-ignored 'credentials.env' next to this file (KEY=VALUE lines)
#   3. the non-secret defaults below (dc_pass defaults to empty)
# ---------------------------------------------------------------------
DEFAULT_TIMEOUT = 300  # seconds per attack module
_CRED_ENV = {"domain": "HARNESS_DOMAIN", "dc_user": "HARNESS_DC_USER",
             "dc_pass": "HARNESS_DC_PASS"}
_CRED_DEFAULTS = {"domain": "lab.local", "dc_user": "Administrator", "dc_pass": ""}


def _read_cred_file():
    """Parse KEY=VALUE lines from a git-ignored credentials.env, if present."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials.env")
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return out


def load_credentials():
    """Resolve credentials from env > credentials.env > non-secret defaults."""
    filed = _read_cred_file()
    creds = {}
    for key, env in _CRED_ENV.items():
        creds[key] = (os.environ.get(env)
                      or filed.get(env) or filed.get(key)
                      or _CRED_DEFAULTS[key])
    return creds


# Resolved once at import for convenience; Context re-resolves per instance.
DEFAULT_CREDENTIALS = load_credentials()


# ---------------------------------------------------------------------
# Target safety — validate the target and (optionally) enforce an allowlist so
# the harness can't be pointed at an arbitrary host by a typo. The allowlist is
# opt-in: env HARNESS_ALLOWLIST (comma/space separated) and/or a git-ignored
# 'allowlist.txt' (one entry per line). With no allowlist configured, behaviour
# is unchanged (any validated target is allowed) — but a configured allowlist
# is enforced hard.
# ---------------------------------------------------------------------
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


def validate_target(target):
    """(ok, reason). Accepts a valid IPv4/IPv6 address or a DNS hostname."""
    if not target or not target.strip():
        return False, "empty target"
    t = target.strip()
    try:
        ipaddress.ip_address(t)
        return True, "valid IP"
    except ValueError:
        pass
    if _HOSTNAME_RE.match(t):
        return True, "valid hostname"
    return False, "not a valid IP address or hostname"


def load_allowlist():
    """Set of allowed targets from env HARNESS_ALLOWLIST + allowlist.txt."""
    entries = set()
    env = os.environ.get("HARNESS_ALLOWLIST", "")
    entries.update(p for p in re.split(r"[,\s]+", env.strip()) if p)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowlist.txt")
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    entries.add(line)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return entries


def target_allowed(target):
    """(allowed, reason). Enforces the allowlist only if one is configured."""
    al = load_allowlist()
    if not al:
        return True, "no allowlist configured (any validated target allowed)"
    return (target in al,
            "in allowlist" if target in al
            else f"NOT in allowlist ({len(al)} entr{'y' if len(al) == 1 else 'ies'} configured)")


def _redact(text, creds):
    """Strip credential VALUES (password especially) out of any text before it
    is echoed to a log — the command header and tool output can otherwise leak
    the cleartext password (e.g. hydra prints it, impacket takes it on argv)."""
    if not text:
        return text
    for key in ("dc_pass", "dc_user"):
        val = creds.get(key)
        if val and len(val) >= 3:            # don't redact trivially short values
            text = text.replace(val, "***")
    return text


def _run_cmd(template, target, creds, timeout):
    try:
        cmd = template.format(target=target, **creds)
    except (KeyError, IndexError, ValueError) as e:
        # a bad template placeholder / missing credential key must not crash
        # the run — report it as an ERROR the classifier surfaces.
        return f"# target: {target}\n\n[ERROR] bad command template ({e!r})"
    # header/logs use a redacted copy — never write the cleartext password out.
    header = f"# command: {_redact(cmd, creds)}\n# target: {target}\n\n"
    try:
        # posix=False on Windows so backslash paths/quoting aren't mangled.
        argv = shlex.split(cmd, posix=(os.name != "nt"))
        if not argv:
            return header + "[ERROR] empty command after parsing"
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        body = (p.stdout or "") + "\n[stderr]\n" + (p.stderr or "")
        return header + _redact(body, creds)
    except subprocess.TimeoutExpired:
        return header + "[TIMEOUT] command exceeded time limit (likely blocked/filtered)"
    except FileNotFoundError:
        return header + "[ERROR] tool not found — is it installed (see preflight.py)?"
    except ValueError as e:
        return header + f"[ERROR] could not parse command ({e})"
    except OSError as e:
        return header + f"[ERROR] could not execute command ({e})"
    except Exception as e:
        return header + f"[ERROR] {_redact(str(e), creds)}"


# ---------------------------------------------------------------------
# Context handed to every attack module
# ---------------------------------------------------------------------
class Context:
    def __init__(self, credentials=None, timeout=DEFAULT_TIMEOUT):
        self.creds = credentials or load_credentials()
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
        import threading
        self.ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.root = os.path.join(base, f"run_{self.ts}")
        self.records = []
        self.meta = {"run": self.ts, "started": datetime.now().isoformat()}
        self._log_fh = None
        self._lock = threading.Lock()   # log/save are safe under concurrent runs
        try:
            os.makedirs(self.root, exist_ok=True)
            self._log_fh = open(os.path.join(self.root, "run.log"), "a")
        except Exception:
            # evidence dir/log unavailable — the run still proceeds; log() and
            # the save_* helpers all degrade gracefully to no-ops with warnings.
            pass

    def log(self, msg):
        """Persist an engine log line to run.log. Never raises — logging must
        not be able to abort a run — and is safe under concurrency."""
        if self._log_fh is None:
            return
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            with self._lock:
                for line in str(msg).splitlines() or [""]:
                    self._log_fh.write(f"[{ts}] {line}\n")
                self._log_fh.flush()
        except Exception:
            pass

    def _dir(self, iteration, attack_id):
        d = os.path.join(self.root, f"iteration_{iteration}", str(attack_id))
        os.makedirs(d, exist_ok=True)
        return d

    def save_run(self, iteration, attack_id, path_name, raw):
        try:
            fn = os.path.join(self._dir(iteration, attack_id), f"{path_name}.log")
            with open(fn, "w") as f:
                f.write(raw if isinstance(raw, str) else str(raw))
            return fn
        except Exception as e:
            self.log(f"[WARN] could not save {attack_id}/{path_name}.log: {e}")
            return None

    def save_result(self, iteration, attack_id, result):
        # keep the record in memory regardless (finalize needs it); persisting
        # the per-attack result.json is best-effort.
        with self._lock:
            self.records.append(result)
        try:
            path = os.path.join(self._dir(iteration, attack_id), "result.json")
            with open(path, "w") as f:
                json.dump(result, f, indent=2, default=str)
        except Exception as e:
            self.log(f"[WARN] could not save {attack_id}/result.json: {e}")

    def finalize(self):
        self.meta["finished"] = datetime.now().isoformat()

        def _safe_write(name, writer):
            try:
                with open(os.path.join(self.root, name), "w", newline="") as f:
                    writer(f)
            except Exception as e:
                self.log(f"[WARN] could not write {name}: {e}")

        _safe_write("summary.json",
                    lambda f: json.dump({"meta": self.meta, "results": self.records},
                                        f, indent=2, default=str))

        cols = ["iteration", "category", "attack", "control_tested", "fix_location",
                "baseline_result", "appliance_result", "verdict", "timestamp"]

        def _write_csv(f):
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in self.records:
                w.writerow({k: r.get(k, "") for k in cols})
        _safe_write("summary.csv", _write_csv)

        agg = {}
        for r in self.records:
            a = r.get("attack", r.get("attack_id", "?"))
            s = agg.setdefault(a, {"cat": r.get("category", ""), "fix": r.get("fix_location", ""),
                                   "blocked": 0, "passed": 0, "other": 0, "n": 0})
            s["n"] += 1
            # single-target mode never sets appliance_result (always "-"), so
            # fall back to baseline_result — otherwise every attack buckets
            # into "other" and the report always reads INCONSISTENT.
            if r.get("appliance_ip") is None:
                v = r.get("baseline_result")
                bucket = "passed" if v == "SUCCESS" else "blocked" if v == "BLOCKED" else "other"
            else:
                v = r.get("appliance_result")
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
        _safe_write("report.txt", lambda f: f.write("\n".join(lines)))

        if self._log_fh is not None:
            try:
                self._log_fh.close()
            except Exception:
                pass
        return self.root


# ---------------------------------------------------------------------
# Classification (raw logs remain the authoritative evidence)
# ---------------------------------------------------------------------
def _match(raw, pat):
    if not pat or raw is None:
        return False
    try:
        return re.search(pat, raw, re.IGNORECASE | re.MULTILINE) is not None
    except re.error:
        # a malformed success_regex/blocked_regex in a module must not crash the
        # run — treat it as "no match" (the raw log stays authoritative).
        return False


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
        os_supported = meta.get("os_supported")   # None => runs on any OS
        os_ok = os_supported is None or platform.system() in os_supported
        out.append({
            "id": meta["id"], "name": meta["name"], "category": meta["category"],
            "requires": reqs, "tools": tools, "missing": missing,
            "needs_root": needs_root, "priv_ok": priv_ok,
            "requires_files": req_files, "missing_files": missing_files,
            "os_supported": os_supported, "os_ok": os_ok,
            "ready": not missing and not missing_files and priv_ok and os_ok,
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
        if not r.get("os_ok", True):
            L.append(f"       OS: not supported on {p['system']} "
                     f"(supports: {', '.join(r['os_supported'])})")
        all_missing.update(r["missing"])
    if all_missing:
        cmds, notes = install_suggestions(sorted(all_missing), pf["package_manager"])
        L += ["", "To install the missing tools:"]
        L += ["  " + c for c in cmds] or ["  (no package mapping — see notes)"]
        L += ["  # " + n for n in notes]
    L.append("=" * 62)
    return "\n".join(L)


# ---------------------------------------------------------------------
# Reachability precheck (recon) — a preliminary, cross-platform TCP-connect
# test of the port(s) each module targets, run BEFORE the exploit so a result
# can tell "service absent / port filtered" apart from "the exploit itself was
# blocked". Pure-socket: no nmap, no root, identical on Linux/macOS/Windows.
#
# IMPORTANT: unlike the tool preflight (which only inspects THIS host), this
# actively contacts the TARGET, so it needs the same authorisation as the
# exploits. It does NOT gate execution — a filtered port may itself be the
# control under test, so modules still run; recon is advisory context.
#
# A module declares the ports it hits in META["ports"] as (proto, port) tuples:
#   [("tcp", 445)]   [("udp", 161)]   [("icmp", None)]   []  (egress-only/none)
# tcp = connect(); udp = best-effort datagram probe (often ambiguous, reported
# as open|filtered); icmp = system ping. Ambiguous results are surfaced as
# "indeterminate" rather than guessed at.
# ---------------------------------------------------------------------

_OPEN_STATES = {"open", "up"}
_CLOSED_STATES = {"closed", "filtered", "unreachable", "unresolved", "down/filtered"}


def probe_tcp(host, port, timeout=2.0):
    """open / closed / filtered / unresolved / unreachable for one TCP port.
    Cross-platform and unprivileged (a plain connect())."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except (socket.timeout, TimeoutError):
        return "filtered"        # no response — dropped/filtered (or slow)
    except ConnectionRefusedError:
        return "closed"          # host reachable, nothing listening on that port
    except socket.gaierror:
        return "unresolved"      # name/DNS did not resolve
    except OSError:
        return "unreachable"     # no route / network error


def probe_udp(host, port, timeout=2.0):
    """Best-effort UDP check (UDP has no handshake, so results are limited):
    open (a reply came back) / closed (ICMP port-unreachable) / open|filtered
    (no reply — the common, ambiguous case) / unreachable / unresolved."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"", (host, port))
        try:
            s.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
    except socket.gaierror:
        return "unresolved"
    except OSError:
        return "unreachable"
    finally:
        s.close()


def probe_icmp(host, timeout=3.0):
    """Best-effort ICMP reachability via the system ping (cross-OS flag: -n on
    Windows, -c elsewhere): up / down/filtered / no-ping / unknown."""
    if shutil.which("ping") is None:
        return "no-ping"
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        p = subprocess.run(["ping", count_flag, "1", host],
                           capture_output=True, text=True, timeout=timeout + 2)
        return "up" if p.returncode == 0 else "down/filtered"
    except Exception:
        return "unknown"


def _probe_one(target, proto, port, timeout):
    if proto == "tcp":
        return probe_tcp(target, port, timeout)
    if proto == "udp":
        return probe_udp(target, port, timeout)
    if proto == "icmp":
        return probe_icmp(target, timeout)
    return "unknown"


def reachability(target, modules, timeout=2.0, workers=32):
    """Probe the port(s) each module targets (tcp connect / best-effort udp /
    icmp ping), CONCURRENTLY (each distinct (proto,port) once). Returns {target,
    probes:[[proto,port,status]...], modules:[{id,name,probes,reachable,category,
    notes}]}. category is suggested|unreachable|indeterminate|noport. Advisory."""
    from concurrent.futures import ThreadPoolExecutor

    # collect the distinct probes needed across all modules, then run them in
    # parallel so filtered ports (each costing a full timeout) don't serialise.
    keys = []
    seen = set()
    for m in modules:
        for spec in m.META.get("ports", []):
            proto, port = spec if isinstance(spec, (list, tuple)) else ("tcp", spec)
            if (proto, port) not in seen:
                seen.add((proto, port))
                keys.append((proto, port))

    cache = {}
    if keys:
        try:
            with ThreadPoolExecutor(max_workers=min(workers, len(keys))) as ex:
                futs = {ex.submit(_probe_one, target, p, port, timeout): (p, port)
                        for (p, port) in keys}
                for fut, key in futs.items():
                    try:
                        cache[key] = fut.result()
                    except Exception:
                        cache[key] = "error"
        except Exception:
            for (p, port) in keys:          # pool unavailable -> sequential
                cache[(p, port)] = _probe_one(target, p, port, timeout)

    results = []
    for m in modules:
        meta = m.META
        probes = []
        for spec in meta.get("ports", []):
            proto, port = spec if isinstance(spec, (list, tuple)) else ("tcp", spec)
            probes.append([proto, port, cache.get((proto, port), "unknown")])
        reachable = any(p[2] in _OPEN_STATES for p in probes)
        if not probes:
            category = "noport"
        elif reachable:
            category = "suggested"
        elif any(p[2] in _CLOSED_STATES for p in probes):
            category = "unreachable"
        else:
            category = "indeterminate"   # e.g. UDP open|filtered — can't tell
        results.append({"id": meta["id"], "name": meta["name"], "probes": probes,
                        "reachable": reachable, "category": category, "notes": []})
    flat = [[proto, port, st] for (proto, port), st in cache.items()]
    return {"target": target, "probes": flat, "modules": results}


def format_reachability_report(rc):
    """Human-readable recon summary from a reachability() result."""
    L = ["=" * 62, f"  RECON — reachability of {rc['target']}", "=" * 62]
    if rc["probes"]:
        L.append("Probes:")
        for proto, port, st in sorted(rc["probes"], key=lambda x: (x[0], x[1] or 0)):
            label = f"{port}/{proto}" if port is not None else proto
            L.append(f"  {label:>9}  {st}")
    else:
        L.append("(no ports to probe among these modules)")

    def names(cat):
        return [r["name"] for r in rc["modules"] if r["category"] == cat]

    L += ["", "Suggested (service reachable): " + (", ".join(names("suggested")) or "none")]
    if names("unreachable"):
        L.append("Not reachable (filtered/closed) — a filtered port may itself be "
                 "the control: " + ", ".join(names("unreachable")))
    if names("indeterminate"):
        L.append("Indeterminate (UDP/ICMP no reply — can't tell open from filtered): "
                 + ", ".join(names("indeterminate")))
    if names("noport"):
        L.append("No port to probe (egress-only): " + ", ".join(names("noport")))
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

        # Wrap every UI callback so a fault in the consumer (GUI, etc.) can never
        # abort a run. on_output/on_status/on_progress take varargs; on_log one.
        def _safe(cb, default):
            cb = cb or default
            def wrapped(*a, **k):
                try:
                    return cb(*a, **k)
                except Exception:
                    return None
            return wrapped

        self.on_log = _safe(on_log, lambda m: None)
        self.on_progress = _safe(on_progress, lambda c, t: None)
        # on_output(attack_id, name, raw_text) — the tool's own full output,
        # for a live "what actually happened" panel (distinct from on_log's
        # short narrative lines).
        self.on_output = _safe(on_output, lambda *a: None)
        # on_status(attack_id, name, iteration, verdict) — one call per
        # attack completion, for a live pass/fail status list.
        self.on_status = _safe(on_status, lambda *a: None)
        self.ctx = Context()
        self._stop = False
        # hard wall-clock cap per module run; None -> ctx.timeout + 60s.
        self.module_hard_timeout = None

    def stop(self):
        self._stop = True

    def _safe_module_run(self, m, ip):
        """Run a module with BOTH an exception boundary and a wall-clock watchdog,
        so neither a crash nor a hang can take down a run. Any exception becomes
        an error string; a module that exceeds the hard cap is abandoned (left as
        a daemon thread) and reported as an error, and the run moves on.

        The cap is generous (per-command timeout + 60s) so it only trips on a
        genuine hang — every module's own subprocess/socket calls already carry
        their own, tighter timeouts. Overridable via self.module_hard_timeout."""
        import threading
        mid = m.META.get("id", "?") if hasattr(m, "META") else "?"
        cap = self.module_hard_timeout or ((self.ctx.timeout or DEFAULT_TIMEOUT) + 60)
        box = {}

        def worker():
            try:
                out = m.run(ip, self.ctx)
                box["out"] = out if isinstance(out, str) else str(out)
            except Exception as e:
                import traceback
                box["out"] = (f"# module {mid} raised while running against {ip}\n\n"
                              f"[ERROR] module crashed: {e.__class__.__name__}: {e}\n\n"
                              + traceback.format_exc())

        t = threading.Thread(target=worker, name=f"mod-{mid}", daemon=True)
        t.start()
        t.join(cap)
        if t.is_alive():
            return (f"# module {mid} vs {ip}\n\n[ERROR] module exceeded the "
                    f"{cap:.0f}s wall-clock watchdog and was abandoned (it may "
                    f"still be running in the background). Treat as inconclusive "
                    f"— check the target/tool for a hang.")
        return box.get("out", f"# module {mid}\n\n[ERROR] module produced no output")

    def run(self, modules, iterations, ev, skip_unready=True, recon=True):
        def log(msg):
            try:
                self.on_log(msg)
            except Exception:
                pass
            ev.log(msg)

        # ----- Target safety: validate + enforce allowlist BEFORE anything -----
        for label, ip in ([("target", self.target_ip)] +
                          ([("appliance", self.appliance_ip)] if self.dual else [])):
            ok, why = validate_target(ip)
            if not ok:
                raise ValueError(f"Invalid {label} '{ip}': {why}")
        allowed, areason = target_allowed(self.target_ip)
        if not allowed:
            raise ValueError(
                f"Target '{self.target_ip}' refused — {areason}. Add it to "
                f"allowlist.txt or HARNESS_ALLOWLIST to proceed.")

        mode = "dual-path (baseline + appliance)" if self.dual else "single-target"
        log(f"Mode: {mode}")
        log(f"Target: {self.target_ip} ({areason})")
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
            if not r.get("os_ok", True):
                reasons.append(f"not supported on {pi['system']}")
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

        # ----- Recon: preliminary reachability of the target's ports ----------
        # Advisory only (does not gate) — a filtered port may BE the control.
        recon_by_id = {}
        if recon:
            try:
                rc = reachability(self.target_ip, modules)
                ev.meta["recon"] = rc
                recon_by_id = {r["id"]: r for r in rc["modules"]}
                if rc["probes"]:
                    log("Recon (reachability of %s): " % self.target_ip
                        + ", ".join(f"{port}/{proto}:{st}"
                                    for proto, port, st in sorted(rc["probes"],
                                                                  key=lambda x: (x[0], x[1] or 0))))
                suggested = [r["name"] for r in rc["modules"] if r["category"] == "suggested"]
                unreach = [r["name"] for r in rc["modules"] if r["category"] == "unreachable"]
                if suggested:
                    log("  suggested (service reachable): " + ", ".join(suggested))
                if unreach:
                    log("  not reachable (filtered/closed) — still running (filtered "
                        "port may be the control): " + ", ".join(unreach))
            except Exception as e:
                log(f"[WARN] recon skipped (non-fatal): {e}")

        # Run the iterations; capture (don't propagate) module-loop faults so the
        # run is crash-proof, but let KeyboardInterrupt/SystemExit through. The
        # finally finalises evidence in ALL cases — without a return inside it
        # (return-in-finally swallows exceptions and is a Py3.14 SyntaxWarning).
        try:
            self._iterate(modules, iterations, ev, skip_unready, ready_ids,
                          pf_by_id, recon_by_id, log)
        except Exception as e:
            import traceback
            log(f"[ERROR] run aborted mid-iteration (non-fatal): {e}")
            log(traceback.format_exc())
        finally:
            try:
                root = ev.finalize()
            except Exception as e:
                log(f"[ERROR] finalize failed: {e}")
                root = ev.root
        return root

    def _iterate(self, modules, iterations, ev, skip_unready, ready_ids,
                 pf_by_id, recon_by_id, log):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        total = iterations * len(modules)
        prog = {"cur": 0}
        plock = threading.Lock()

        def bump():
            with plock:
                prog["cur"] += 1
                c = prog["cur"]
            self.on_progress(c, total)

        conc = max(1, int(getattr(self, "concurrency", 1) or 1))

        for it in range(1, iterations + 1):
            if self._stop:
                break
            log(f"\n=== Iteration: {it} ===")

            # Parallel-safe = concurrency requested, module is ready, and not
            # flagged serial (DoS/brute tests must run ALONE so they can't
            # pollute each other's rate-limit/latency results). Everything else
            # (skips + serial + all modules when conc==1) runs sequentially.
            parallel, serial = [], []
            for m in modules:
                mid = m.META["id"]
                unready = skip_unready and mid not in ready_ids
                is_serial = bool(m.META.get("serial"))
                if conc > 1 and not unready and not is_serial:
                    parallel.append(m)
                else:
                    serial.append(m)

            if parallel:
                log(f"  running {len(parallel)} module(s) with {conc} workers")
                with ThreadPoolExecutor(max_workers=min(conc, len(parallel))) as ex:
                    list(ex.map(lambda mm: self._process_module(
                        mm, it, skip_unready, ready_ids, pf_by_id, recon_by_id,
                        ev, log, bump), parallel))
            for m in serial:
                if self._stop:
                    break
                self._process_module(m, it, skip_unready, ready_ids, pf_by_id,
                                     recon_by_id, ev, log, bump)

    def _process_module(self, m, it, skip_unready, ready_ids, pf_by_id,
                        recon_by_id, ev, log, bump):
        """Run (or skip) one module for one iteration and record the result.
        Safe to call from worker threads (Evidence is locked, callbacks wrapped)."""
        if self._stop:
            return
        meta = m.META
        log(f"  [{meta['category']}] {meta['name']}")

        # Skip modules whose prerequisites aren't met, recording WHY.
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
            if not r.get("os_ok", True):
                bits.append(f"not supported on {platform.system()}")
            verdict = "PREREQ-MISSING — skipped (" + "; ".join(bits) + ")"
            b, a = "PREREQ-MISSING", "-"
            log(f"     target: [{b}]  -> {verdict}")
            self.on_status(meta["id"], meta["name"], it, b, verdict)
            self._record(ev, it, meta, b, a, verdict, recon_by_id)
            bump()
            return

        target_raw = self._safe_module_run(m, self.target_ip)
        ev.save_run(it, meta["id"], "target", target_raw)
        self.on_output(meta["id"], meta["name"], target_raw)

        if self.dual:
            app_raw = self._safe_module_run(m, self.appliance_ip)
            ev.save_run(it, meta["id"], "through-appliance", app_raw)
            b, a, verdict = classify(meta, target_raw, app_raw)
            log(f"     baseline: [{b}]  appliance: [{a}]  -> {verdict}")
        else:
            ok = _match(target_raw, meta.get("success_regex"))
            authfail = _match(target_raw, AUTHFAIL_REGEX)
            blocked = _match(target_raw, meta.get("blocked_regex")) or "[TIMEOUT]" in target_raw
            rr = recon_by_id.get(meta["id"])
            port_filtered = rr is not None and rr["category"] == "unreachable"
            if ok:
                b, verdict = "SUCCESS", "attack succeeded against target"
            elif authfail:
                b, verdict = "AUTH-FAILED", "credential error — fix credentials (HARNESS_DC_PASS), not a control result"
            elif blocked:
                b, verdict = "BLOCKED", "attack blocked/unreachable"
                if port_filtered:
                    verdict += " (recon: target port filtered/closed — segmentation or service absent)"
            elif port_filtered:
                b = "BLOCKED"
                verdict = "attack blocked — recon shows target port filtered/closed (segmentation or service absent)"
            else:
                hint = _error_hint(target_raw)
                b = "NO-RESULT"
                verdict = f"no result — {hint}" if hint else "no result — review raw log"
            a = "-"
            log(f"     target: [{b}]  -> {verdict}")

        self.on_status(meta["id"], meta["name"], it, b, verdict)
        self._record(ev, it, meta, b, a, verdict, recon_by_id)
        bump()

    def _record(self, ev, it, meta, b, a, verdict, recon_by_id):
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
            "reachability": recon_by_id.get(meta["id"]),
            "timestamp": datetime.now().isoformat(),
        })
