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
import errno
import json
import shlex
import shutil
import socket
import platform
import ipaddress
import importlib
import time
import html as _html
import subprocess
from datetime import datetime

# Harness release version — bump on meaningful changes. Surfaced in the CLI
# (`--version` + run header), the GUI title, every report, and each run's
# summary.json meta, so any evidence folder is traceable to the build that made
# it (alongside the git short-SHA in `engine_version`). Single source of truth —
# cli.py / gui.py import this.
VERSION = "1.2.0"

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
             "dc_pass": "HARNESS_DC_PASS",
             # SSH creds are SEPARATE from the DC creds: a dual-role target is
             # both an SSH host (e.g. labadmin) AND a Windows DC front
             # (Administrator), and one identity can't serve both. ssh_brute
             # uses these and falls back to dc_user/dc_pass only when unset.
             "ssh_user": "HARNESS_SSH_USER", "ssh_pass": "HARNESS_SSH_PASS"}
_CRED_DEFAULTS = {"domain": "lab.local", "dc_user": "Administrator", "dc_pass": "",
                  "ssh_user": "", "ssh_pass": ""}


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
# Operator config — the DESTINATIONS/infra the attack-sim (USS) modules aim at
# (your redirector/VPS, a domain you control, a canary endpoint, DoH providers,
# a segmented pivot target, ...). NEVER hardcode live attacker infra inside a
# module — read it from here so the same module works across engagements and so
# nothing points at real infrastructure by default. Precedence:
#   1. env  HARNESS_CFG_<KEY>   (e.g. HARNESS_CFG_ATTACKER_VPS=1.2.3.4)
#   2. a git-ignored 'config.json' next to this file
#   3. the (mostly empty) built-in defaults below
# A module that needs a value which is unset degrades to a safe no-op with a
# clear "[SKIP] ... not configured" line instead of pointing somewhere real.
# ---------------------------------------------------------------------
_CFG_DEFAULTS = {
    "attacker_vps": "",            # host/ip of your redirector/VPS (443 tunnels, SSH-over-443, SOCKS)
    "attacker_domain": "",         # a domain you are authoritative for (DNS tunnel / attacker-DoH / NRD)
    "attacker_doh": "",            # your DoH endpoint URL (attacker-controlled-resolver test)
    "canary_url": "",              # an HTTPS endpoint that logs a hit (DLP canary POST)
    "canary_dns_zone": "",         # zone you control, for DNS-exfil proof (falls back to attacker_domain)
    "internal_pivot_target": "",   # host:port of a segmented service to reach via the 443 SOCKS pivot
    "front_domain": "",            # a frontable CDN edge domain (domain fronting SNI)
    "front_host": "",              # the real Host to reach behind the front
    "published_app_url": "",       # a published 443 app URL (WAF evasion / exposed-mgmt probe)
    "external_resolver": "8.8.8.8",  # a public resolver, for the "is internal DNS forced" test
    "doh_providers": [             # public DoH endpoints (family B multi-provider)
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
        "https://dns.quad9.net:5053/dns-query",
    ],
    "beacon_seconds": 60,          # family G beacon window (total)
    "beacon_interval": 5,          # family G beacon sleep between callbacks
}


def _read_cfg_file():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    try:
        with open(path) as f:
            return json.load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        import sys
        sys.stderr.write(f"[WARN] config.json could not be parsed ({e}) — using "
                         "env/defaults only; your destinations may be inactive.\n")
        return {}


def load_config():
    """Resolve operator config from env > config.json > defaults."""
    cfg = dict(_CFG_DEFAULTS)
    for k, v in _read_cfg_file().items():
        if v not in (None, ""):
            cfg[k] = v
    for k in list(cfg.keys()):
        env = os.environ.get(f"HARNESS_CFG_{k.upper()}")
        if not env:
            continue
        dflt = _CFG_DEFAULTS.get(k)
        # Coerce to the DEFAULT value's type so a numeric key (e.g.
        # HARNESS_CFG_BEACON_SECONDS=60) doesn't arrive as the string "60" and
        # break a module doing arithmetic on it. (bool before int — bool is an int.)
        if isinstance(cfg[k], list) or isinstance(dflt, list):
            cfg[k] = [x.strip() for x in env.split(",") if x.strip()]
        elif isinstance(dflt, bool):
            cfg[k] = env.strip().lower() in ("1", "true", "yes", "on")
        elif isinstance(dflt, int):
            try:
                cfg[k] = int(env)
            except ValueError:
                cfg[k] = dflt
        elif isinstance(dflt, float):
            try:
                cfg[k] = float(env)
            except ValueError:
                cfg[k] = dflt
        else:
            cfg[k] = env
    return cfg


_ROE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".roe_accepted")


def roe_accepted():
    """Rules-of-engagement confirmed WITHOUT the per-run flag — a durable, explicit
    opt-in (the operator did it once). This is not a silent bypass: it still
    requires a deliberate `--accept-roe` / HARNESS_CONFIRM_ROE=1, just once."""
    if os.environ.get("HARNESS_CONFIRM_ROE", "").lower() in ("1", "true", "yes"):
        return True
    return os.path.exists(_ROE_FILE)


def accept_roe():
    """Record a durable ROE opt-in (git-ignored .roe_accepted). Returns the path."""
    try:
        with open(_ROE_FILE, "w") as f:
            f.write(datetime.now().isoformat() + " rules-of-engagement accepted\n")
        return _ROE_FILE
    except Exception:
        return None


def load_detections():
    """Operator-supplied blue-team detections, so an attack that PASSED the
    boundary can be scored DETECTED (passed but the SOC alerted) rather than as a
    silent finding — which is the purple-team deliverable (Blocked / Detected /
    Passed-undetected). Source: env HARNESS_DETECTIONS (a path) or a git-ignored
    'detections.json' next to this file. Accepts either mapping or list form:
        {"egress_tunnel_brokers": true}
        {"doh_multi": {"note": "Splunk alert TUN-014", "source": "SIEM"}}
        [{"id": "socks_pivot", "note": "EDR flagged", "source": "CrowdStrike"}]
    Returns {attack_id: {"note":..., "source":...}}. Never raises."""
    path = os.environ.get("HARNESS_DETECTIONS") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "detections.json")
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        import sys
        sys.stderr.write(f"[WARN] detections.json could not be parsed ({e}) — no "
                         "blue-team detections loaded (attacks won't score DETECTED).\n")
        return {}
    out = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if v is True:
                out[k] = {}
            elif isinstance(v, dict):
                out[k] = v
    elif isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict) and rec.get("id"):
                out[rec["id"]] = rec
    return out


# ---------------------------------------------------------------------
# Boundary port policy (SD-WAN / firewall allow-list). The engagement boundary
# permits only a defined set of ports; an attack whose SERVICE port is DENIED by
# the policy is expected to be stopped at the SEGMENTATION boundary, NOT by the
# IPS/WAF — so a BLOCKED on such a port must NEVER be credited to the IPS. The
# harness evaluates this during preflight (before any scanning) and annotates the
# verdicts so "segmentation did its job" is kept distinct from "the IPS caught it".
#
# Default = "Polisi Standard Security v1.3" (the engagement's standard). Override
# with a git-ignored 'port_policy.json' (or $HARNESS_PORT_POLICY path) of shape:
#   {"name": "...", "allow": {"tcp":[...], "udp":[...]}, "deny": {"tcp":[...], "udp":[...]}}
# ---------------------------------------------------------------------
def _ports(*spec):
    """Expand a mix of ints and (lo,hi) inclusive ranges into a set of ints."""
    out = set()
    for s in spec:
        if isinstance(s, tuple):
            out.update(range(s[0], s[1] + 1))
        else:
            out.add(int(s))
    return out

# Polisi Standard Security v1.3 — "Standard Services" (+ cloud-VC) = allowed;
# the red "Vulnerable Ports" = denied. Transcribed from the engagement policy.
_POLISI_V13 = {
    "name": "Polisi Standard Security v1.3",
    "allow": {
        "tcp": _ports(20, 21, 22, 53, 80, 81, 88, 123, 389, 443, 465, 587, 993,
                      1935, 2048, 2065, 2082, 2083, 2095, 2096, 3478, 5004, 5222,
                      7777, 7778, 8080, 8081, 8082, 8181, 8383, 8443, 8801, 8802, 8888),
        "udp": _ports(53, 80, 443, 2048, 2065, 2082, 2095, 2096, 2257, (3478, 3481),
                      5004, 7778, 8081, 8181, 8383, 8443, (8801, 8810), 8888, 9000,
                      (19302, 19309), 33434),
    },
    "deny": {
        "tcp": _ports(135, 139, 445, 593, 1025, 5554, 9995, 9996),
        "udp": _ports(135, 137, 138, 445),
    },
}


def load_port_policy():
    """Active boundary port policy — Polisi v1.3 by default, overridable via a
    git-ignored 'port_policy.json' or $HARNESS_PORT_POLICY. Returns
    {name, allow:{tcp:set,udp:set}, deny:{tcp:set,udp:set}}. Never raises."""
    pol = {"name": _POLISI_V13["name"],
           "allow": {"tcp": set(_POLISI_V13["allow"]["tcp"]), "udp": set(_POLISI_V13["allow"]["udp"])},
           "deny":  {"tcp": set(_POLISI_V13["deny"]["tcp"]),  "udp": set(_POLISI_V13["deny"]["udp"])}}
    path = os.environ.get("HARNESS_PORT_POLICY") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "port_policy.json")
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            pol["name"] = data.get("name", pol["name"])
            for sect in ("allow", "deny"):
                d = data.get(sect) or {}
                for proto in ("tcp", "udp"):
                    if proto in d:
                        pol[sect][proto] = {int(x) for x in d[proto]}
    except FileNotFoundError:
        pass
    except Exception as e:
        # A malformed port_policy.json must not silently revert to the built-in
        # default and leave the operator thinking their custom policy is active.
        import sys as _sys
        print(f"[port-policy] WARNING: could not load {path} ({e.__class__.__name__}: "
              f"{e}); using built-in default '{pol['name']}'.", file=_sys.stderr)
    return pol


def port_policy_status(proto, port, policy):
    """Per-port verdict against the policy: 'denied' (explicitly vulnerable/
    blocked), 'allowed' (permitted service), or 'unlisted' (default-deny)."""
    proto = "udp" if str(proto).lower() == "udp" else "tcp"
    if port in policy["deny"][proto]:
        return "denied"
    if port in policy["allow"][proto]:
        return "allowed"
    return "unlisted"


def module_policy(meta, policy):
    """Policy outcome for a module from its DECLARED service ports (not the lab's
    NAT alternate — the policy governs the service, not the forwarding trick).
    Returns {outcome, ports:[(proto,port,status)...]}:
      'allowed' = at least one attack port is permitted, so the attack reaches the
                  boundary and the IPS/WAF is the control actually under test;
      'blocked' = every attack port is denied/unlisted, so it's expected to be
                  stopped at the SEGMENTATION boundary (a BLOCKED is NOT an IPS win);
      'egress'  = no fixed inbound TCP/UDP port (egress/ICMP) — policy n/a."""
    specs = []
    for spec in meta.get("ports", []) or []:
        proto, port = spec if isinstance(spec, (list, tuple)) else ("tcp", spec)
        if port is None:
            continue
        specs.append((proto, int(port), port_policy_status(proto, int(port), policy)))
    if not specs:
        return {"outcome": "egress", "ports": []}
    outcome = "allowed" if any(s[2] == "allowed" for s in specs) else "blocked"
    return {"outcome": outcome, "ports": specs}


# ---------------------------------------------------------------------
# Per-target memory — remember the last per-target options (source IP, cloud
# SMB/RPC toggle + ports) so an engineer re-running the SAME script against the
# next target doesn't re-type them. Git-ignored '.target_memory.json'. Keyed by
# target IP/host. Never raises.
# ---------------------------------------------------------------------
_TARGET_MEM = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".target_memory.json")


def load_target_memory():
    try:
        with open(_TARGET_MEM) as f:
            return json.load(f) or {}
    except Exception:
        return {}


def recall_target(target):
    """Return the saved options dict for a target (source/cloud/smb_port/rpc_port
    and per-target creds domain/dc_user/dc_pass), or {}."""
    if not target:
        return {}
    return load_target_memory().get(target.strip(), {})


def remember_target(target, **fields):
    """Persist per-target options; only non-None fields overwrite. May hold
    per-target credentials, so the file is written 0600. Best-effort."""
    if not target:
        return
    mem = load_target_memory()
    rec = mem.get(target.strip(), {})
    rec.update({k: v for k, v in fields.items() if v is not None})
    rec["last_used"] = datetime.now().isoformat()
    mem[target.strip()] = rec
    try:
        # owner-only perms (it can contain a DC password). chmod explicitly too —
        # O_CREAT's mode is ignored for a file that already exists.
        fd = os.open(_TARGET_MEM, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(mem, f, indent=2)
        try:
            os.chmod(_TARGET_MEM, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            with open(_TARGET_MEM, "w") as f:
                json.dump(mem, f, indent=2)
            # still enforce owner-only perms on the fallback path — this file can
            # hold a DC/SSH password, and the primary path chmods 0600 too.
            try:
                os.chmod(_TARGET_MEM, 0o600)
            except OSError:
                pass
        except Exception:
            pass


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
    # A dotted all-numeric string that FAILED ip_address (e.g. 192.168.1.300, or
    # 10.0.0.1.2) is a MALFORMED IP, not a hostname. Accepting it as a hostname is
    # dangerous: every probe then silently fails and the whole run reports BLOCKED
    # for a target that was never reached. Reject it with a clear reason.
    if re.match(r"^\d{1,}(?:\.\d{1,})+$", t):
        return False, "malformed IP address (octet out of range / wrong length)"
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


def source_ip_bindable(ip):
    """True if `ip` is a local address we can bind egress sockets to. A source IP
    that isn't on any local interface (e.g. a public NAT address typed by mistake)
    can't be bound, so an egress-bind request against it would silently no-op."""
    if not ip:
        return False
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    except Exception:
        fam = socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            s.bind((ip, 0))
            return True
        finally:
            s.close()
    except OSError:
        return False


def _redact(text, creds):
    """Strip credential VALUES (password especially) out of any text before it
    is echoed to a log — the command header and tool output can otherwise leak
    the cleartext password (e.g. hydra prints it, impacket takes it on argv)."""
    if not text:
        return text
    for key in ("dc_pass", "dc_user", "ssh_pass", "ssh_user"):
        val = creds.get(key)
        if val and len(val) >= 3:            # don't redact trivially short values
            text = text.replace(val, "***")
    return text


# --debug: inject a verbose flag into a SMALL allowlist of tools so the raw logs
# carry the tool's own debug trace. Opt-in only (ctx.debug); kept conservative so
# an injected flag can't break an unrelated command.
_DEBUG_TOOL_FLAGS = {"curl": "-v", "ldapsearch": "-v", "hydra": "-d"}


def _inject_debug_flag(argv):
    if not argv:
        return argv
    base = os.path.basename(argv[0]).lower()
    flag = _DEBUG_TOOL_FLAGS.get(base)
    if flag and flag not in argv:
        return [argv[0], flag] + argv[1:]
    # impacket CLIs/examples accept a global -debug (impacket-X / X.py / the
    # "python3 .../X.py" resolver form). Insert it right after the script.
    joined = " ".join(argv).lower()
    if ("-debug" not in argv and ("impacket" in joined or re.search(
            r"(secretsdump|getuserspns|getnpusers|psexec|wmiexec)\.py", joined))):
        idx = 2 if base in ("python", "python3") else 1
        return argv[:idx] + ["-debug"] + argv[idx:]
    return argv


def _run_cmd(template, target, creds, timeout, debug=False):
    try:
        cmd = template.format(target=target, **creds)
    except (KeyError, IndexError, ValueError) as e:
        # a bad template placeholder / missing credential key must not crash
        # the run — report it as an ERROR the classifier surfaces.
        return f"# target: {target}\n\n[ERROR] bad command template ({e!r})"
    # posix=False on Windows so backslash paths/quoting aren't mangled.
    try:
        argv = shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError as e:
        return (f"# command: {_redact(cmd, creds)}\n# target: {target}\n\n"
                f"[ERROR] could not parse command ({e})")
    if debug:
        argv = _inject_debug_flag(argv)
    # header/logs use a redacted copy — never write the cleartext password out.
    header = f"# command: {_redact(' '.join(argv), creds)}\n# target: {target}\n\n"
    if not argv:
        return header + "[ERROR] empty command after parsing"
    try:
        # stdin=DEVNULL + start_new_session: detach from the controlling
        # terminal so a tool that prompts for a password (impacket/hydra call
        # getpass, which otherwise opens /dev/tty and prints "Password:" into
        # the operator's terminal mid-run, blocking and polluting the output)
        # gets EOF instead and fails cleanly into captured stderr.
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, start_new_session=True)
        body = (p.stdout or "") + "\n[stderr]\n" + (p.stderr or "")
        return header + _redact(body, creds)
    except subprocess.TimeoutExpired:
        return header + "[TIMEOUT] command exceeded time limit (likely blocked/filtered)"
    except FileNotFoundError:
        return header + "[ERROR] tool not found — is it installed (see preflight.py)?"
    except OSError as e:
        return header + f"[ERROR] could not execute command ({e})"
    except Exception as e:
        return header + f"[ERROR] {_redact(str(e), creds)}"


# ---------------------------------------------------------------------
# Context handed to every attack module
# ---------------------------------------------------------------------
class Context:
    def __init__(self, credentials=None, timeout=DEFAULT_TIMEOUT, port_overrides=None,
                 config=None, source_ip=None, allow_active=False, debug=False):
        self.creds = credentials or load_credentials()
        self.timeout = timeout
        # --debug / HARNESS_DEBUG: ask tools for their own verbose trace (curl -v,
        # ldapsearch -v, hydra -d, impacket -debug) and keep the full per-module
        # stream on the console. Modules can also read ctx.debug themselves.
        self.debug = bool(debug) or os.environ.get("HARNESS_DEBUG", "").lower() in ("1", "true", "yes")
        # per-module port overrides: {name: port}. Also read from env
        # HARNESS_PORT_<NAME> (e.g. HARNESS_PORT_LOG4SHELL=8983). A module calls
        # ctx.get_port("log4shell", 8080) to honour a custom port.
        self.port_overrides = dict(port_overrides or {})
        # operator config (destinations/infra the USS modules aim at) — see
        # load_config(). Read with ctx.cfg("attacker_vps").
        self.config = config if config is not None else load_config()
        # source IP to bind egress sockets to (assumed-breach foothold #2 / a
        # specific VRF interface). None -> OS default route. Modules that build a
        # socket should bind to this when set. From env HARNESS_SOURCE_IP or CLI.
        self.source_ip = source_ip or os.environ.get("HARNESS_SOURCE_IP") or None
        # ACTIVE-ESTABLISHMENT GATE. False (default) -> live modules (real
        # tunnels / SOCKS pivots / DNS tunnels / data exfil to your infra) run in
        # NON-DESTRUCTIVE INDICATOR mode only. True (CLI --active) -> they may
        # actually establish. Off by default so nothing invasive runs by accident.
        self.allow_active = bool(allow_active)

    def cfg(self, key, default=None):
        """Read an operator-config value (see load_config); empty -> default."""
        v = self.config.get(key, default) if self.config else default
        return v if v not in (None, "") else default

    def bind_source(self, sock):
        """Bind a socket to ctx.source_ip if configured (best-effort; a bad bind
        is swallowed so a module still works on the default route)."""
        if self.source_ip:
            try:
                sock.bind((self.source_ip, 0))
            except OSError:
                pass
        return sock

    def get_port(self, name, default):
        """Resolve a module's target port: explicit override > env > default."""
        if name in self.port_overrides:
            try:
                return int(self.port_overrides[name])
            except (TypeError, ValueError):
                pass
        env = os.environ.get(f"HARNESS_PORT_{name.upper()}")
        if env:
            try:
                return int(env)
            except ValueError:
                pass
        return default

    def run_cmd(self, template, target):
        """Run an external command (curl/hydra/impacket/etc.); returns full
        raw output. Template may use {target} and any credential key
        (domain, dc_user, dc_pass)."""
        return _run_cmd(template, target, self.creds, self.timeout,
                        debug=getattr(self, "debug", False))


# ---------------------------------------------------------------------
# Evidence logger
# ---------------------------------------------------------------------
def _claim_run_dir(base, name):
    """Atomically claim a UNIQUE run directory `base/name`, returning its path.

    Evidence folder names are minute-resolution (DD-MM-HH-MM, no seconds), so two
    runs started in the same minute — two Claude sessions, GUI+CLI, or parallel
    fleet jobs — want the SAME folder. A check-then-create (os.path.exists +
    makedirs(exist_ok=True)) is a TOCTOU race: both pass the check, both create,
    and their iteration_N/<attack>/ results silently interleave in one dir. So we
    try os.mkdir (atomic — raises FileExistsError if the name is already taken)
    and bump -2/-3/... on a clash, guaranteeing each process gets its OWN dir with
    no interleaving. Degrades to a nominal (uncreated) path if creation is
    impossible, so the caller's save_* helpers just no-op with warnings."""
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:
        return os.path.join(base, name)
    candidate = os.path.join(base, name)
    n = 1
    while True:
        try:
            os.mkdir(candidate)
            return candidate
        except FileExistsError:
            n += 1
            candidate = os.path.join(base, f"{name}-{n}")
            if n > 100000:          # pathological; stop looping
                return candidate
        except Exception:
            return candidate        # permission/other — let save_* degrade


def _atomic_write(path, writer, newline=None):
    """Write `path` via a temp file + os.replace() so a concurrent reader never
    sees a half-written file and two writers can't corrupt each other. The temp
    name carries the pid so parallel writers to the same path don't collide on
    the temp itself. `writer(f)` performs the actual write."""
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w", newline=newline) as f:
            writer(f)
        os.replace(tmp, path)       # atomic on POSIX within one filesystem
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise


def _engine_version():
    """Best-effort engine revision (git short SHA) for evidence provenance; '' if
    unavailable. Never raises or blocks the run."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        out = subprocess.run(["git", "-C", here, "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=3)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return ""


class Evidence:
    @staticmethod
    def _slug(label):
        """Filesystem-safe tag from a target (keep it readable: dots/colons -> _)."""
        s = re.sub(r"[^A-Za-z0-9._-]", "_", str(label))
        return s.strip("_")[:40]

    def __init__(self, base="evidence", label=None):
        import threading
        self.ts = datetime.now().strftime("%d-%m-%H-%M")   # day-month-hour-minute
        # In a multi-target scan each target gets its own Evidence; a bare
        # run_<ts> would make them run_<ts> / run_<ts>-2 — collision-safe but you
        # can't tell WHICH target is which. A label (the target) names the dir
        # run_<ts>__<target> so it's self-describing.
        name = f"run_{self.ts}" + (f"__{self._slug(label)}" if label else "")
        # Claim the dir ATOMICALLY (os.mkdir, not exists-check + makedirs) so two
        # concurrent runs in the same minute can never share/interleave a dir —
        # see _claim_run_dir(). Each run gets its own run_<ts>[-N].
        self.root = _claim_run_dir(base, name)
        self.records = []
        self.meta = {"run": self.ts, "started": datetime.now().isoformat()}
        self._log_fh = None
        self._lock = threading.Lock()   # log/save are safe under concurrent runs
        try:
            # _claim_run_dir already created self.root (or returned a nominal path
            # if creation was impossible, in which case this open just fails and
            # logging degrades to a no-op — the run still proceeds).
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
            _atomic_write(path, lambda f: json.dump(result, f, indent=2, default=str))
        except Exception as e:
            self.log(f"[WARN] could not save {attack_id}/result.json: {e}")

    def finalize(self):
        self.meta["finished"] = datetime.now().isoformat()

        # Verdict distribution + contamination counts baked into meta, so
        # summary.json / INDEX.md are self-describing and a reader can see at a
        # glance how many verdicts are poisoned (SUSPECT = BLOCKED that may be an
        # IP ban; INCONCLUSIVE = never tested, source in IPS quarantine).
        # Dedup to ONE verdict per MODULE (its most-significant across iterations,
        # per _V_ORDER) before tallying — otherwise with >1 iteration a module
        # counts N times and finding/detected/blocked/suspect inflate past what the
        # per-module table in report.txt / report.html / summary CSV actually shows.
        _bymod = {}
        for r in self.records:
            mid = r.get("attack_id") or r.get("attack")
            v = (r.get("appliance_result") if r.get("appliance_ip") is not None
                 else r.get("baseline_result")) or "?"
            e = _bymod.setdefault(mid, {"vs": [], "suspect": False})
            e["vs"].append(v)
            if "SUSPECT" in (r.get("verdict") or ""):
                e["suspect"] = True
        _dist, _suspect = {}, 0
        for e in _bymod.values():
            v = next((x for x in self._V_ORDER if x in e["vs"]), (e["vs"] or ["?"])[0])
            _dist[v] = _dist.get(v, 0) + 1
            if e["suspect"]:
                _suspect += 1
        self.meta["verdicts"] = _dist
        self.meta["finding_count"] = _dist.get("SUCCESS", 0)
        self.meta["inconclusive_count"] = _dist.get("INCONCLUSIVE", 0)
        self.meta["suspect_count"] = _suspect
        _durs = [r.get("duration_s") for r in self.records if r.get("duration_s") is not None]
        if _durs:
            self.meta["total_duration_s"] = round(sum(_durs), 1)

        def _safe_write(name, writer):
            # temp-file + os.replace so a reader (or another session tailing the
            # evidence) never catches a half-written summary/report.
            try:
                _atomic_write(os.path.join(self.root, name), writer, newline="")
            except Exception as e:
                self.log(f"[WARN] could not write {name}: {e}")

        _safe_write("summary.json",
                    lambda f: json.dump({"meta": self.meta, "results": self.records},
                                        f, indent=2, default=str))

        # One row per (attack x iteration) — e.g. 10 attacks x 2 iterations =
        # 20 rows. csv.DictWriter quotes/escapes each field per RFC4180
        # (embedded commas, quotes, newlines) automatically; passing the raw
        # output string straight through is correct — don't hand-escape it,
        # that would double-escape and corrupt the file.
        OUTPUT_CELL_LIMIT = 4000  # Excel caps a cell at 32,767 chars; stay well under it
        cols = ["iteration", "mode", "target_ip", "source_ip", "test_type",
                "family", "direction", "category", "attack", "ports", "recon",
                "policy", "tactic", "mitre", "cwe", "control_tested",
                "fix_location", "baseline_result", "appliance_result", "passed",
                "verdict", "detected_source", "duration_s", "timestamp", "output"]

        def _write_csv(f):
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in self.records:
                row = {}
                for k in cols:
                    v = r.get(k, "")
                    row[k] = ", ".join(v) if isinstance(v, list) else v
                out = row.get("output") or ""
                if len(out) > OUTPUT_CELL_LIMIT:
                    row["output"] = (out[:OUTPUT_CELL_LIMIT] +
                                     f"\n...[truncated, {len(out)} chars total — "
                                     f"full output in iteration_{r.get('iteration')}/"
                                     f"{r.get('attack_id')}/target.log]")
                w.writerow(row)
        _safe_write("summary.csv", _write_csv)

        agg = {}
        for r in self.records:
            a = r.get("attack", r.get("attack_id", "?"))
            s = agg.setdefault(a, {"cat": r.get("category", ""), "fix": r.get("fix_location", ""),
                                   "blocked": 0, "passed": 0, "detected": 0,
                                   "skipped": 0, "other": 0, "n": 0})
            s["n"] += 1
            # single-target mode never sets appliance_result (always "-"), so
            # fall back to baseline_result — otherwise every attack buckets
            # into "other" and the report always reads INCONSISTENT.
            if r.get("appliance_ip") is None:
                v = r.get("baseline_result")
                bucket = ("passed" if v == "SUCCESS" else "detected" if v == "DETECTED"
                          else "blocked" if v == "BLOCKED" else "skipped" if v == "SKIPPED"
                          else "other")
            else:
                v = r.get("appliance_result")
                bucket = ("blocked" if v == "BLOCKED" else "detected" if v == "DETECTED"
                          else "passed" if v == "SUCCESS" else "skipped" if v == "SKIPPED"
                          else "other")
            s[bucket] += 1

        lines = ["=" * 64, "  CONTROL VALIDATION HARNESS — REPORT",
                 f"  Run: {self.ts}   ·   Harness v{VERSION}"
                 + (f" ({self.meta['engine_version']})" if self.meta.get("engine_version") else "")
                 + f"   ·   Posture: {self.meta.get('mode', 'blackbox').upper()}",
                 "=" * 64,
                 "  Verdicts: GAP=passed-undetected (finding) · DETECT=passed but "
                 "SOC alerted · OK=blocked · REVIEW=mixed", ""]
        _pp = self.meta.get("port_policy")
        if _pp:
            lines += [f"  Port policy [{_pp.get('name','')}]: {_pp.get('allowed',0)} on allowed "
                      f"ports (IPS/WAF under test) · {_pp.get('blocked_by_policy',0)} denied "
                      f"(expected segmentation block) · {_pp.get('egress',0)} egress/ICMP", ""]

        # Contamination banner — SUSPECT (BLOCKED that may be a source-IP ban) and
        # INCONCLUSIVE (never tested; source in IPS quarantine) are NOT per-attack
        # control results, so surface them up top; they must not be read as real
        # BLOCKEDs. Lists the exact modules to re-run clean.
        _susp_mods = sorted({r.get("attack", r.get("attack_id", "?")) for r in self.records
                             if "SUSPECT" in (r.get("verdict") or "")})
        _inc_mods = sorted({r.get("attack", r.get("attack_id", "?")) for r in self.records
                            if r.get("baseline_result") == "INCONCLUSIVE"})
        if _susp_mods or _inc_mods:
            lines += ["  " + "!" * 60,
                      "  ** CONTAMINATED RESULTS — these are NOT control wins; re-run clean",
                      "     (whitelist the tester source on the appliance / wait out the",
                      "     quarantine), then re-test ONLY these:"]
            if _inc_mods:
                lines.append("       INCONCLUSIVE (IPS quarantine, not tested): " + ", ".join(_inc_mods))
            if _susp_mods:
                lines.append("       SUSPECT (BLOCKED may be the ban, not the control): " + ", ".join(_susp_mods))
            lines += [f"     -> python3 cli.py --suspect {self.root}",
                      "  " + "!" * 60, ""]

        # ---- modern per-module results: verdict distribution + a grouped table ----
        _VORDER = ["SUCCESS", "DETECTED", "BLOCKED", "NO-SERVICE",
                   "AUTH-FAILED", "NO-RESULT", "INCONCLUSIVE", "SKIPPED", "PREREQ-MISSING"]
        permod = {}
        for r in self.records:
            mid = r.get("attack_id") or r.get("attack")
            v = (r.get("appliance_result") if r.get("appliance_ip") is not None
                 else r.get("baseline_result")) or "?"
            d = permod.setdefault(mid, {"name": r.get("attack", mid), "cat": r.get("category", ""),
                                        "mitre": ", ".join(r.get("mitre", []) or []),
                                        "dir": r.get("direction", ""), "vs": []})
            d["vs"].append(v)
        for d in permod.values():
            d["v"] = next((x for x in _VORDER if x in d["vs"]), d["vs"][0] if d["vs"] else "?")
        dist = {}
        for d in permod.values():
            dist[d["v"]] = dist.get(d["v"], 0) + 1
        total = len(permod) or 1
        mxd = max(dist.values()) if dist else 1
        lines += ["  VERDICT DISTRIBUTION  (%d modules)" % total]
        for v in _VORDER:
            if v in dist:
                meter = "#" * (int(round(24 * dist[v] / mxd)) or 1)
                lines.append(f"    {v:<16} {meter:<24} {dist[v]:>2}/{total}")
        findings = dist.get("SUCCESS", 0)
        lines += ["    " + "-" * 44,
                  f"    => {findings} got through (finding) · {dist.get('DETECTED', 0)} detected "
                  f"· {dist.get('BLOCKED', 0)} blocked", "",
                  "  RESULTS BY MODULE", "  " + "-" * 62]
        cur = None
        for d in sorted(permod.values(),
                        key=lambda x: (x["cat"], _VORDER.index(x["v"]) if x["v"] in _VORDER else 9, x["name"])):
            if d["cat"] != cur:
                cur = d["cat"]
                lines.append("  [%s]" % cur)
            dirn = (" %s" % d["dir"]) if d["dir"] else ""
            lines.append(f"    {d['v']:<15} {d['name']:<40} {d['mitre']}{dirn}")
        lines += ["", "=" * 64, "  PER-ATTACK CONSISTENCY", "=" * 64, ""]

        for a, s in agg.items():
            # "consistent" = every iteration landed in the SAME bucket. All five
            # buckets must be candidates — omitting 'other'/'skipped' made a clean
            # single-bucket run (e.g. one skipped iteration) falsely read as
            # INCONSISTENT.
            consistent = any(s[b] == s["n"] for b in
                             ("blocked", "passed", "detected", "skipped", "other"))
            tag = "consistent" if consistent else "INCONSISTENT"
            # a single passed-undetected iteration is the finding, so GAP wins;
            # then DETECT (passed but alerted), then OK (all blocked), then SKIPPED
            # (nothing ran — n/a or unconfigured, NOT a control result), else REVIEW.
            if s["passed"]:
                verdict = "GAP (passed-undetected)"
            elif s["detected"] and not s["other"] and not s["skipped"]:
                verdict = "DETECT (passed but alerted)"
            elif s["blocked"] == s["n"]:
                verdict = "OK (blocked)"
            elif s["skipped"] == s["n"]:
                verdict = "SKIPPED (not run — n/a or unconfigured)"
            else:
                verdict = "REVIEW"
            lines += [f"[{s['cat']}] {a}",
                      f"    blocked {s['blocked']}/{s['n']}  passed {s['passed']}/{s['n']}  "
                      f"detected {s['detected']}/{s['n']}  skipped {s['skipped']}/{s['n']}  "
                      f"other {s['other']}/{s['n']}  -> {verdict} ({tag})",
                      f"    fix: {s['fix']}", ""]

        # ----- BAS coverage: MITRE ATT&CK + CWE (standards-aligned reporting) --
        # Per technique: which attacks map to it and whether any PASSED (gap) vs
        # all BLOCKED (control held). "outcome" here is the worst case observed.
        def _outcome(r):
            v = r.get("appliance_result") if r.get("appliance_ip") is not None \
                else r.get("baseline_result")
            return "SUCCESS" if v == "SUCCESS" else \
                   "DETECTED" if v == "DETECTED" else \
                   "BLOCKED" if v == "BLOCKED" else "OTHER"

        tech = {}
        cwe = {}
        for r in self.records:
            oc = _outcome(r)
            for t in (r.get("mitre") or ["(unmapped)"]):
                e = tech.setdefault(t, {"tactic": r.get("tactic", ""), "attacks": set(),
                                        "passed": 0, "detected": 0, "blocked": 0, "other": 0})
                e["attacks"].add(r.get("attack", r.get("attack_id", "?")))
                e["passed" if oc == "SUCCESS" else "detected" if oc == "DETECTED"
                  else "blocked" if oc == "BLOCKED" else "other"] += 1
            for c in (r.get("cwe") or []):
                cwe.setdefault(c, set()).add(r.get("attack", "?"))

        def _status(e):
            # GAP = something passed undetected (the finding); DETECT = passed but
            # every pass-through was alerted; OK = all blocked; else REVIEW.
            if e["passed"]:
                return "GAP"
            if e["detected"] and not e["other"] and not e["passed"]:
                return "DETECT"
            if e["blocked"] and not e["other"] and not e["detected"]:
                return "OK"
            return "REVIEW"

        cov = {t: {"tactic": e["tactic"], "attacks": sorted(e["attacks"]),
                   "passed": e["passed"], "detected": e["detected"],
                   "blocked": e["blocked"], "other": e["other"],
                   "status": _status(e)}
               for t, e in tech.items()}
        self.meta["attack_coverage"] = cov
        self.meta["cwe_coverage"] = {c: sorted(v) for c, v in cwe.items()}
        cves = sorted({r.get("cve") for r in self.records if r.get("cve")})
        self.meta["cve_coverage"] = cves
        # rewrite summary.json now that meta carries the coverage
        _safe_write("summary.json",
                    lambda f: json.dump({"meta": self.meta, "results": self.records},
                                        f, indent=2, default=str))

        # ATT&CK Navigator layer (import at attack-navigator to visualise coverage)
        _COLOR = {"GAP": "#f85149", "DETECT": "#db6d28", "OK": "#3fb950", "REVIEW": "#e3a008"}
        navigator = {
            "name": f"MyGovNet BAS {self.ts}",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Control-validation coverage (GAP=passed-undetected, "
                           "DETECT=passed but alerted, OK=blocked, REVIEW=mixed).",
            "techniques": [
                {"techniqueID": t.split(".")[0], "score": 100,
                 "color": _COLOR.get(e["status"], "#8b90a6"),
                 "enabled": True,
                 "comment": f"{e['status']}: {', '.join(e['attacks'])}"}
                for t, e in cov.items() if t.startswith("T")
            ],
            "gradient": {"colors": ["#3fb950", "#e3a008", "#f85149"], "minValue": 0, "maxValue": 100},
            "legendItems": [{"label": "GAP (passed-undetected)", "color": "#f85149"},
                            {"label": "DETECT (passed but alerted)", "color": "#db6d28"},
                            {"label": "OK (blocked)", "color": "#3fb950"},
                            {"label": "REVIEW (mixed)", "color": "#e3a008"}],
        }
        _safe_write("attack_navigator_layer.json",
                    lambda f: json.dump(navigator, f, indent=2))

        lines += ["", "=" * 64, "  MITRE ATT&CK COVERAGE", "=" * 64]
        for t in sorted(cov):
            e = cov[t]
            lines.append(f"{t:<12} [{e['tactic']}]  -> {e['status']}  "
                         f"(passed {e['passed']} / detected {e['detected']} / "
                         f"blocked {e['blocked']} / other {e['other']})")
            lines.append(f"    {', '.join(e['attacks'])}")
        if cwe:
            lines += ["", "  CWE COVERAGE"]
            for c in sorted(cwe):
                lines.append(f"    {c}: {', '.join(sorted(cwe[c]))}")
        if cves:
            lines += ["", "  CVE COVERAGE", "    " + ", ".join(cves)]

        lines += ["", "ATT&CK Navigator layer: attack_navigator_layer.json",
                  f"Evidence: {self.root}"]
        _safe_write("report.txt", lambda f: f.write("\n".join(lines)))

        # shareable self-contained HTML report (verdict table + coverage), no deps
        _safe_write("report.html", self._write_html)

        # one-line entry in a sibling INDEX.md so all runs are scannable at a glance
        self._append_index()

        if self._log_fh is not None:
            try:
                self._log_fh.close()
            except Exception:
                pass
        return self.root

    def _append_index(self):
        """Append ONE line describing this run to a sibling INDEX.md, so every run
        under the evidence dir is scannable without opening each folder. A single
        short append to an O_APPEND file is atomic on POSIX, so concurrent runs
        (two sessions / fleet jobs) can't corrupt each other's lines. Best-effort."""
        try:
            m = self.meta
            d = m.get("verdicts", {})
            flags = []
            if m.get("inconclusive_count"):
                flags.append(f"INCONCLUSIVE={m['inconclusive_count']}")
            if m.get("suspect_count"):
                flags.append(f"SUSPECT={m['suspect_count']}")
            flag_s = ("  [" + " ".join(flags) + "]") if flags else ""
            line = (f"- `{os.path.basename(self.root)}` · {m.get('run','')} · "
                    f"v{m.get('harness_version', VERSION)} · "
                    f"target `{m.get('target_ip','?')}`"
                    + (f" · site {m['site_id']}" if m.get("site_id") else "")
                    + f" · {m.get('module_count','?')} modules · "
                    f"finding={m.get('finding_count',0)} "
                    f"detected={d.get('DETECTED',0)} blocked={d.get('BLOCKED',0)}"
                    + flag_s + "\n")
            parent = os.path.dirname(self.root) or "."
            idx = os.path.join(parent, "INDEX.md")
            new = not os.path.exists(idx)
            with open(idx, "a") as f:        # O_APPEND: atomic for a short line
                if new:
                    f.write("# Evidence run index\n\n")
                f.write(line)
        except Exception as e:
            self.log(f"[WARN] could not update INDEX.md: {e}")

    _V_ORDER = ["SUCCESS", "DETECTED", "BLOCKED", "NO-SERVICE",
                "AUTH-FAILED", "NO-RESULT", "INCONCLUSIVE", "SKIPPED", "PREREQ-MISSING"]
    _V_COLOR = {"SUCCESS": "#e5484d", "DETECTED": "#f5a524",
                "BLOCKED": "#30a46c", "NO-SERVICE": "#4493f8", "AUTH-FAILED": "#e2a336",
                "NO-RESULT": "#e2a336", "INCONCLUSIVE": "#a371f7",
                "SKIPPED": "#8b949e", "PREREQ-MISSING": "#8b949e"}
    # short gloss per verdict for the per-iteration ITERATIONS column (mirrors
    # cli.py's _VERDICT_GLOSS_SHORT so the HTML report and the terminal table
    # read the same way) — N copies of it (one per iteration) share one cell.
    _V_GLOSS_SHORT = {
        "SUCCESS": "finding", "DETECTED": "SOC alerted",
        "BLOCKED": "blocked", "NO-SERVICE": "no service", "AUTH-FAILED": "bad creds",
        "NO-RESULT": "review log", "INCONCLUSIVE": "indeterminate",
        "SKIPPED": "skipped", "PREREQ-MISSING": "missing prereq",
    }

    def _write_html(self, f):
        """A self-contained, shareable HTML evidence summary (inline CSS, no deps):
        run meta, verdict distribution, the per-module table, and ATT&CK/CWE/CVE."""
        e = _html.escape
        recs = self.records or []
        by = {}
        for r in recs:
            mid = r.get("attack_id") or r.get("attack")
            d = by.setdefault(mid, {"name": r.get("attack", mid), "cat": r.get("category", ""),
                                    "mitre": ", ".join(r.get("mitre", []) or []),
                                    "cwe": ", ".join(r.get("cwe", []) or []),
                                    "dur": None, "vs": [], "verdicts": {}, "iters": []})
            # In dual-path (appliance) mode the AUTHORITATIVE verdict is the
            # appliance leg, not the allow-all baseline (which is only OK/AUTH-
            # FAILED/FAIL-inconclusive). report.txt + summary.json already select
            # appliance_result when appliance_ip is set; report.html must match, or
            # the shareable HTML shows meaningless verdicts for the SD-WAN use case.
            br = (r.get("appliance_result") if r.get("appliance_ip") is not None
                  else r.get("baseline_result")) or "?"
            d["vs"].append(br)
            d["verdicts"][br] = r.get("verdict", "")
            # one entry per iteration, in run order, so the report can show how
            # the verdict varied run-to-run instead of collapsing straight to
            # the single most-significant one (a later iteration landing in an
            # ambiguous band, e.g. icmp_flood's loss delta, was otherwise invisible).
            d["iters"].append({"n": r.get("iteration"), "v": br,
                                "detail": r.get("verdict", "")})
            if r.get("duration_s") is not None:
                d["dur"] = max(d["dur"] or 0.0, r["duration_s"])
        for d in by.values():
            d["v"] = next((v for v in self._V_ORDER if v in d["vs"]), (d["vs"] or ["?"])[0])
        dist = {}
        for d in by.values():
            dist[d["v"]] = dist.get(d["v"], 0) + 1
        n = len(by) or 1
        m = self.meta
        site = m.get("site_id", "")
        tgt = recs[0].get("target_ip", "") if recs else ""

        def color(v):
            return self._V_COLOR.get(v, "#8b949e")

        # ONE table throughout. With >1 iteration, ITERATIONS replaces DETAIL
        # outright (same column count, mirrors cli.py's terminal table exactly)
        # and carries each iteration's own verdict + short gloss — the
        # aggregate Verdict column only ever shows the single most-significant
        # iteration (_V_ORDER), which otherwise hid a later iteration landing
        # in a different bucket entirely (e.g. icmp_flood's loss-delta falling
        # in the ambiguous band on one run and not another).
        show_iters = any((r.get("iteration") or 1) > 1 for r in recs)
        rows = []
        for i, d in enumerate(sorted(by.values(), key=lambda x: (
                x["cat"], self._V_ORDER.index(x["v"]) if x["v"] in self._V_ORDER else 9, x["name"])), 1):
            if show_iters:
                iters_sorted = sorted((it for it in d["iters"] if it["n"] is not None),
                                       key=lambda it: it["n"])
                last_cell = " | ".join(
                    f'{it["n"]}:{e(it["v"])} ({e(self._V_GLOSS_SHORT.get(it["v"], "?"))})'
                    for it in iters_sorted)
            else:
                last_cell = e(d["verdicts"].get(d["v"], ""))
            rows.append(
                f'<tr><td class=num>{i}</td>'
                f'<td><span class=pill style="background:{color(d["v"])}">{e(d["v"])}</span></td>'
                f'<td>{e(d["name"])}</td><td class=dim>{e(d["cat"])}</td>'
                f'<td class=dim>{e(d["mitre"])}</td><td class=dim>{e(d["cwe"])}</td>'
                f'<td class=dim>{("%.1fs" % d["dur"]) if d["dur"] is not None else ""}</td>'
                f'<td class=verdict>{last_cell}</td></tr>')
        bars = []
        for v in self._V_ORDER:
            if v not in dist:
                continue
            pct = 100.0 * dist[v] / n
            bars.append(
                f'<div class=bar><span class=lbl style="color:{color(v)}">{e(v)}</span>'
                f'<span class=meter><span style="width:{pct:.0f}%;background:{color(v)}"></span></span>'
                f'<span class=cnt>{dist[v]}/{n}</span></div>')
        findings = dist.get("SUCCESS", 0)
        # Contamination banner (SUSPECT / INCONCLUSIVE) — see report.txt rationale.
        susp_mods = sorted({r.get("attack", "?") for r in recs
                            if "SUSPECT" in (r.get("verdict") or "")})
        inc_mods = sorted({r.get("attack", "?") for r in recs
                           if r.get("baseline_result") == "INCONCLUSIVE"})
        banner = ""
        if susp_mods or inc_mods:
            parts = []
            if inc_mods:
                parts.append("<b>INCONCLUSIVE</b> (IPS quarantine, not tested): " + e(", ".join(inc_mods)))
            if susp_mods:
                parts.append("<b>SUSPECT</b> (BLOCKED may be the ban, not the control): " + e(", ".join(susp_mods)))
            banner = ('<div class=warn><b>&#9888; Contaminated results — NOT control wins.</b> '
                      'Re-run clean (whitelist the tester source on the appliance / wait out the '
                      'quarantine):<br>' + "<br>".join(parts) + '</div>')
        ver = e("v" + VERSION + ((" (" + m.get("engine_version", "") + ")") if m.get("engine_version") else ""))
        f.write(f"""<!doctype html><html><head><meta charset=utf-8>
<title>Control Validation — {e(tgt)}</title><style>
body{{font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}}
h1{{font-size:18px;margin:0 0 4px}} .meta{{color:#8b949e;font-size:13px;margin-bottom:16px}}
table{{border-collapse:collapse;width:100%;margin-top:16px;font-size:13px}}
th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
th{{color:#8b949e;font-weight:600;border-bottom:2px solid #30363d}}
.num{{color:#6e7681;width:28px}} .dim{{color:#8b949e}} .verdict{{color:#8b949e;font-size:12px;max-width:380px}}
.pill{{color:#fff;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}}
.bar{{display:flex;align-items:center;gap:8px;margin:3px 0}} .lbl{{width:120px;font-weight:600}}
.meter{{flex:0 0 220px;height:10px;background:#21262d;border-radius:5px;overflow:hidden}}
.meter>span{{display:block;height:100%}} .cnt{{color:#8b949e}}
.foot{{margin-top:14px;font-weight:600}} code{{color:#58a6ff}}
.warn{{background:#2d2411;border:1px solid #9e6a03;border-left:4px solid #e3a008;
color:#f0d58c;padding:10px 12px;border-radius:6px;margin:12px 0;font-size:13px}}
</style></head><body>
<h1>Control Validation Harness — Results</h1>
<div class=meta>{('SITE ' + e(site) + ' &middot; ') if site else ''}target <code>{e(tgt)}</code>
&middot; run {e(m.get('run',''))} &middot; harness {ver} &middot; posture {e(m.get('mode','blackbox'))}
&middot; {n} module(s) &middot; {e(str(m.get('finished','')))}</div>
{banner}
{''.join(bars)}
<table><thead><tr><th>#</th><th>Verdict</th><th>Module</th><th>Category</th>
<th>MITRE</th><th>CWE</th><th>Time</th><th>{"Iterations" if show_iters else "Detail"}</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<div class=foot>&rarr; {findings} finding(s) got through &middot; {dist.get('DETECTED',0)} detected
&middot; {dist.get('BLOCKED',0)} blocked</div>
<div class=meta style="margin-top:10px">Raw evidence, summary.json/csv and the ATT&amp;CK Navigator layer
are in this run folder. Verdicts: red = got through (finding) &middot; orange = detected &middot;
green = blocked &middot; blue = no-service.</div>
</body></html>""")


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
# NOT anchored to line-start: a module may legitimately put the marker at the
# END of a line (e.g. "... no IPv6 target. [SKIP]"), and an anchored ^ missed
# those — so a deliberate skip leaked through to blocked_regex and mis-scored as
# BLOCKED. Match the marker anywhere on a line.
_ERROR_MARKER = re.compile(r"(?:\[ERROR\]|\S*ERROR\S*:).*$", re.MULTILINE)
_WARN_MARKER = re.compile(r"\[WARN\].*$", re.MULTILINE)
# [SKIP] = a module deliberately did nothing (e.g. an active-establishment
# module with no infra configured, or --active not set) — surface WHY so the
# NO-RESULT verdict isn't a mystery.
_SKIP_MARKER = re.compile(r"\[SKIP\].*$", re.MULTILINE)
# [PREREQ-MISSING] = a module discovered at RUNTIME that a LOCAL prerequisite is
# missing (e.g. kerberoast needs `faketime` once the host clock is skewed past
# Kerberos' 5-min window). Not a control result and not a tool crash — the test
# simply could not run. Scored PREREQ-MISSING (same bucket as a preflight skip),
# carrying the module's own reason. Checked before the blocked/no-service branches
# so the missing prerequisite can't be miscredited to the control.
_PREREQ_MARKER = re.compile(r"\[PREREQ-MISSING\].*$", re.MULTILINE)
# [INCONCLUSIVE] = a module ran but legitimately CANNOT decide (a UDP probe with
# no handshake; a coercion that fired but whose callback can't be observed from
# this vantage point). Distinct from NO-RESULT (a tool fault with no signal): the
# module is deliberately declaring the test indeterminate and telling the operator
# what to verify, so the reason isn't lost behind a mute "review raw log".
_INCONCLUSIVE_MARKER = re.compile(r"\[INCONCLUSIVE\].*$", re.MULTILINE)
# Harness-INTERNAL failures: the module crashed (exception boundary), the
# wall-clock watchdog abandoned a hang, it produced no output, or run_cmd could
# not build/launch the command. These are TOOL faults, not the control blocking
# the attack — so even when recon shows the port filtered they must score
# NO-RESULT, never a false BLOCKED (which would credit the control for a crash).
_TOOL_FAIL_MARKER = re.compile(
    r"\[ERROR\] module crashed:"
    r"|wall-clock watchdog and was abandoned"
    r"|\[ERROR\] module produced no output"
    r"|\[ERROR\] (?:bad command template|could not parse command"
    r"|empty command after parsing|tool not found|could not execute command)",
    re.IGNORECASE)


def _error_hint(raw):
    # prefer an actual ERROR line (the definitive reason) over a WARN (a
    # secondary side-note) — e.g. petitpotam prints both when not root, and
    # the "RESPONDER-PRIV-ERROR: needs root" line is the one worth surfacing.
    m = _ERROR_MARKER.search(raw) or _WARN_MARKER.search(raw) or _SKIP_MARKER.search(raw)
    return m.group(0).strip() if m else None


# Credential/auth failures (bad creds) are NOT a control result — checked
# before blocked_regex so a broad "STATUS_" style pattern can't misreport a
# wrong password as "control blocked it".
AUTHFAIL_REGEX = (
    r"STATUS_LOGON_FAILURE|STATUS_ACCOUNT_DISABLED|STATUS_PASSWORD_EXPIRED|"
    r"invalidCredentials|KRB_AP_ERR_MODIFIED|KDC_ERR_(?:PREAUTH_FAILED|C_PRINCIPAL_UNKNOWN)|"
    r"AcceptSecurityContext error|Authentication failure|Login incorrect"
)

# A REFUSED/RST means the host answered "nothing is listening here" -> the SERVICE
# is absent, NOT that the SD-WAN dropped the traffic. That must NOT be scored as a
# control block. (A dropped/timed-out packet = FILTERED = likely a control block.)
REFUSED_REGEX = (
    r"Connection refused|actively refused|ECONNREFUSED|Errno 111|"
    r"Can't contact LDAP server|Couldn't connect to server|Failed to connect"
)


def classify(meta, base_raw, app_raw):
    succ, blk = meta.get("success_regex"), meta.get("blocked_regex")
    base_ok = _match(base_raw, succ)
    base_authfail = _match(base_raw, AUTHFAIL_REGEX)
    app_ok = _match(app_raw, succ)
    app_authfail = _match(app_raw, AUTHFAIL_REGEX)
    # A module that printed [SKIP] did nothing — never score that as BLOCKED
    # (a win for the control). Checked before app_blocked.
    app_skipped = not app_ok and _SKIP_MARKER.search(app_raw or "") is not None
    # Parity with the single-target classifier: a module can self-declare a missing
    # runtime prerequisite or an indeterminate result, and those must win over the
    # blocked/no-service branches (never miscredited to the control).
    app_prereq = not app_ok and _PREREQ_MARKER.search(app_raw or "") is not None
    app_inconcl = not app_ok and _INCONCLUSIVE_MARKER.search(app_raw or "") is not None
    app_blocked = not app_skipped and (_match(app_raw, blk) or "[TIMEOUT]" in app_raw)
    # A RST / "connection refused" through the appliance = the service is ABSENT,
    # not the control dropping the attack — mirror single-target NO-SERVICE. Only
    # when the module's own blocked_regex didn't already claim it (BLOCKED wins, so
    # a module that treats refused AS a block — e.g. its blocked_regex lists
    # "refused" — still scores BLOCKED).
    app_refused = not app_ok and not app_blocked and _match(app_raw, REFUSED_REGEX)

    baseline_result = "OK" if base_ok else "AUTH-FAILED" if base_authfail else "FAIL (inconclusive)"
    # "SUCCESS" is the unified "got through, undetected" label — the SAME word the
    # single-target path uses (there is no separate "PASSED" verdict anymore).
    if app_ok:
        appliance_result = "SUCCESS"
    elif app_authfail:
        appliance_result = "AUTH-FAILED"      # parity: credential error, not a control result
    elif app_prereq:
        appliance_result = "PREREQ-MISSING"   # parity: runtime prerequisite missing
    elif app_inconcl:
        appliance_result = "INCONCLUSIVE"     # parity: module couldn't decide
    elif app_skipped:
        appliance_result = "SKIPPED"           # parity: module did nothing (was NO-RESULT)
    elif app_refused:
        appliance_result = "NO-SERVICE"        # parity: port closed/refused = service absent
    elif app_blocked:
        appliance_result = "BLOCKED"
    else:
        appliance_result = "NO-RESULT"

    if base_authfail and not base_ok:
        verdict = "CREDENTIAL ERROR — fix core.DEFAULT_CREDENTIALS, not a control result"
    elif not base_ok:
        verdict = "INCONCLUSIVE (baseline did not succeed — check target/service)"
    elif appliance_result == "BLOCKED":
        verdict = "CONTROL WORKING (blocked)"
    elif appliance_result == "NO-SERVICE":
        verdict = ("NO-SERVICE through the appliance (port closed / connection refused — the "
                   "service is absent, NOT a control block; the attack could not apply)")
    elif appliance_result == "AUTH-FAILED":
        verdict = "AUTH-FAILED through the appliance (credential error, not a control result)"
    elif appliance_result == "PREREQ-MISSING":
        verdict = "PREREQ-MISSING through the appliance (a prerequisite is missing — not a control result)"
    elif appliance_result == "INCONCLUSIVE":
        verdict = "INCONCLUSIVE through the appliance (the test could not be decided)"
    elif appliance_result == "SKIPPED":
        verdict = "SKIPPED through the appliance (module did nothing — n/a or unconfigured; not a control result)"
    elif appliance_result == "SUCCESS":
        verdict = "FINDING (attack passed the appliance)"
    else:
        verdict = "REVIEW (no result through appliance — block vs monitor?)"
    return baseline_result, appliance_result, verdict


def _detection_phrasing(note):
    """Word a DETECTED verdict by the NATURE of the detection note, instead of a
    blanket "detection works, prevention did not" (which over-claims for a plain
    session-log ALLOW — that is the appliance LOGGING+ALLOWING a flow, i.e.
    visibility, not an IPS alert, and nothing tried to prevent it). The notes are
    produced by additional/sangfor_ingest.py with predictable substrings."""
    n = (note or "").lower()
    if "prevention=yes" in n or "signature" in n:
        # a real IPS/AV signature fired (and claims prevention) — yet the attack
        # still returned a result, so prevention did NOT actually stop this probe.
        return ("an IPS/appliance SIGNATURE fired on this attack (a genuine detection) "
                "but the probe still got through — detection works, prevention did not")
    if "prevention=no" in n:
        return ("an IPS/appliance signature matched in detect-only mode (no prevention) "
                "— detection works, prevention is not enabled")
    if "deny" in n:
        return ("the appliance DENIED this flow at the policy/session level — confirm "
                "against the raw log whether the attack was actually prevented, since it "
                "still returned a result")
    if "allow" in n or "session-logged" in n or "seen" in n:
        # the crux of the user's question: a session-log ALLOW is VISIBILITY, not
        # a security detection, and prevention was never in scope on an allowed policy.
        return ("the appliance LOGGED and ALLOWED this flow — this is visibility / "
                "telemetry only (NOT an IPS alert, and prevention was not in scope on an "
                "allowed policy). Confirm your SOC actually ALERTS on it before counting "
                "it as a detection")
    return ("the appliance/SOC has a record of this attack (detection); prevention did "
            "not block it")


def _detection_is_real(note):
    """Decide whether a detection NOTE is a GENUINE security detection or merely
    the appliance's own policy REFERENCE / telemetry.

    A session-log line like "session-logged tcp/21: ALLOW (policy=Outbound_NPSA)"
    is the appliance reporting that it SAW and PASSED the flow — visibility, not a
    detection, and no prevention was ever attempted. Scoring that as DETECTED
    (orange, "detection worked") HIDES a real finding: the attack passed
    undetected. Per the operator's instruction (ORG2026-70) the policy reference is
    "just a reference", not a test result — so only a fired IPS SIGNATURE, an
    explicit prevention verdict, or an active DENY counts as a real detection; a
    plain ALLOW / session-log / "seen" is telemetry, and the attack keeps the
    verdict its OWN output earned (SUCCESS when it got through)."""
    n = (note or "").lower()
    if "signature" in n or "prevention=" in n:
        return True
    # a session-log DENY is the appliance actively blocking at policy level (an
    # action), distinct from a passive ALLOW reference. "MIXED"/"ALLOW"/plain
    # "session-logged" are telemetry only.
    if "deny" in n and "allow" not in n:
        return True
    return False


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


def sudo_available():
    """True if we're already root, or `sudo` exists to elevate with."""
    return is_privileged() or shutil.which("sudo") is not None


# A safe default degree of parallelism: enough to overlap network latency across
# the reachable modules, but low enough not to look like a flood to the target /
# SD-WAN. DoS/brute modules run serially regardless (META["serial"]).
RECOMMENDED_WORKERS = 4


def sudo_nopasswd_works(timeout=4):
    """Best-effort: does `sudo -n` run WITHOUT prompting? True if we're root or a
    passwordless sudo rule applies. Note: with command-specific NOPASSWD this can
    be False yet `sudo -n <that-tool>` still works — so treat False as 'maybe'."""
    if is_privileged():
        return True
    if not shutil.which("sudo"):
        return False
    try:
        p = subprocess.run(["sudo", "-n", "true"], capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode == 0
    except Exception:
        return False


def sudo_unlock(password, timeout=10):
    """Cache the sudo timestamp with the given password (`sudo -S -v`) so later
    `sudo -n` calls succeed WITHOUT a NOPASSWD rule and WITHOUT running the whole
    harness as root. The password is used only for this one call and never stored
    or logged. Returns (ok, message). Cache lasts ~15 min (sudo's timestamp).
    Run from the same terminal/session that launched the harness so the cached
    ticket applies to the modules' `sudo -n` calls."""
    if is_privileged():
        return True, "already root"
    if not shutil.which("sudo"):
        return False, "sudo not found"
    try:
        p = subprocess.run(["sudo", "-S", "-v"], input=(password or "") + "\n",
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode == 0:
            return True, "sudo credentials cached (~15 min) — root modules can now run"
        last = (p.stderr or "").strip().splitlines()
        return False, (last[-1] if last else "authentication failed")
    except subprocess.TimeoutExpired:
        return False, "sudo timed out"
    except Exception as e:
        return False, str(e)


def privilege_status(modules=None):
    """Summarise how root-needing modules will get their privileges, so a run
    can be started informed. Returns a dict the GUI/CLI can render."""
    root = is_privileged()
    sudo = shutil.which("sudo") is not None
    cached = sudo and sudo_nopasswd_works()   # NOPASSWD or a live cached ticket
    needs = [m.META["name"] for m in (modules or [])
             if getattr(m, "META", {}).get("needs_root")]
    if root:
        how = "running as root/admin"
    elif cached:
        how = "passwordless/cached sudo available — tools self-elevate via `sudo -n`"
    elif sudo:
        how = "sudo needs a password — click 'Unlock sudo' to cache it (~15 min)"
    else:
        how = "NOT elevated and no sudo — root-needing modules will be skipped"
    return {"root": root, "sudo_present": sudo, "sudo_nopasswd": cached,
            "can_unlock": sudo and not root and not cached,
            "needs_root_modules": needs, "how": how}


def sudo_prefix():
    """Command prefix to elevate a single tool: [] when already root or no sudo,
    else ['sudo', '-n']. The -n (NON-INTERACTIVE) is the whole point: sudo will
    NEVER prompt for a password — it runs when NOPASSWD covers the command, or
    fails immediately with a clear message, so a run can't hang on a hidden
    password prompt behind a GUI. Elevate the actual privileged binary (hping3,
    responder) so a per-command NOPASSWD rule for that binary matches."""
    if is_privileged() or not shutil.which("sudo"):
        return []
    return ["sudo", "-n"]


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


# Python libraries the in-process modules import — (import-to-test, pip-name).
# Single source of truth for requirements.txt / bootstrap / preflight. The
# import name is a DEEP one so it exercises the real chain (e.g. dns.asyncquery
# and cryptography.hazmat.asn1, which a stale/shadowed cryptography breaks).
PY_PACKAGES = [
    ("impacket.examples.secretsdump", "impacket"),
    ("ldap3", "ldap3"),
    ("ldapdomaindump", "ldapdomaindump"),
    ("dns.asyncquery", "dnspython"),
    ("cryptography.hazmat.asn1", "cryptography"),
]


def check_python_packages():
    """Import each in-process dependency and report status — the 'are the Python
    packages prepared?' gate. [{import, pip, ok, error}]. Never raises."""
    out = []
    for imp, pip_name in PY_PACKAGES:
        try:
            importlib.import_module(imp)
            out.append({"import": imp, "pip": pip_name, "ok": True, "error": ""})
        except Exception as e:
            out.append({"import": imp, "pip": pip_name, "ok": False,
                        "error": f"{e.__class__.__name__}: {e}"})
    return out


def preflight(modules, want_versions=False):
    """Check every module's declared requirements. Returns:
      {platform, privileged, package_manager, python_packages, modules: [...]}
    where each per-module dict has ready/missing/missing_files/missing_py/priv_ok."""
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
        # Python-module deps (requires_py): a module that shells out is covered by
        # `requires`, but an IN-PROCESS one (impacket/cryptography) can import fine
        # at module load yet die on a deeper lazy import at runtime — e.g. a stale
        # user-site `cryptography` shadowing a newer one breaks
        # `cryptography.hazmat.asn1`, so noPac/sAMAccountName NO-RESULT while
        # shutil.which sees nothing wrong. Actually importing the declared paths
        # catches that class before the run.
        missing_py = []
        for modpath in meta.get("requires_py", []):
            try:
                importlib.import_module(modpath)
            except Exception:
                missing_py.append(modpath)
        # a root-needing module is OK if we're root OR sudo exists to elevate the
        # tool non-interactively (the module runs it via `sudo -n <tool>`; if
        # NOPASSWD isn't configured for it, the module reports a clear error).
        priv_ok = (not needs_root) or priv or (shutil.which("sudo") is not None)
        os_supported = meta.get("os_supported")   # None => runs on any OS
        os_ok = os_supported is None or platform.system() in os_supported
        out.append({
            "id": meta["id"], "name": meta["name"], "category": meta["category"],
            "requires": reqs, "tools": tools, "missing": missing,
            "needs_root": needs_root, "priv_ok": priv_ok,
            "requires_files": req_files, "missing_files": missing_files,
            "requires_py": list(meta.get("requires_py", [])), "missing_py": missing_py,
            "os_supported": os_supported, "os_ok": os_ok,
            "ready": not missing and not missing_files and not missing_py
                     and priv_ok and os_ok,
        })
    return {"platform": platform_info(), "privileged": priv,
            "package_manager": pm, "python_packages": check_python_packages(),
            "modules": out}


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
          f"Pkg mgr  : {pf['package_manager'] or 'not detected'}"]
    # Python packages (requirements.txt) — the in-process AD modules need these.
    pyp = pf.get("python_packages") or []
    if pyp:
        ok_n = sum(1 for d in pyp if d["ok"])
        L += ["", f"Python packages: {ok_n}/{len(pyp)} importable (for in-process AD modules)"]
        for d in pyp:
            if d["ok"]:
                L.append(f"  [OK] {d['pip']}")
            else:
                L.append(f"  [XX] {d['pip']} — import {d['import']} FAILS ({d['error']})")
        if ok_n < len(pyp):
            L.append("  fix: python3 -m pip install -r requirements.txt  "
                     "(a stale user-site cryptography? rm -rf <usersite>/cryptography*)")
    L += ["", f"Modules ready: {ready_n}/{len(pf['modules'])}", ""]
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
        if r.get("missing_py"):
            L.append(f"       python import FAILS: {', '.join(r['missing_py'])} "
                     "(stale/shadowed lib? e.g. rm a user-site cryptography)")
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


# Protocol-aware UDP probes: an empty datagram elicits no reply from most
# services, so UDP would almost always look like the ambiguous "open|filtered".
# A real request makes an open service answer -> definitive "open".
#  - DNS (53/5353): a standard A? google.com query (RD set).
_DNS_QUERY = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
              b"\x06google\x03com\x00\x00\x01\x00\x01")
#  - SNMP (161): a v1 GET-request for sysDescr.0 (1.3.6.1.2.1.1.1.0), community
#    "public" — an SNMP agent that honours it replies (if the community differs
#    there's no reply, which correctly stays ambiguous).
_SNMP_GET = bytes.fromhex(
    "302902010004067075626c6963a01c020400000000020100020100"
    "300e300c06082b060102010101000500")
#  - QUIC / DoQ (443/853 udp): a long-header Initial with a forced-unknown
#    version, padded to the 1200-byte minimum, so a QUIC server MUST answer with
#    a Version-Negotiation packet. HTTP/3 and DNS-over-QUIC both ride QUIC, so
#    this one probe covers both.
_QUIC_VN = (b"\xc0" + b"\x1a\x2a\x3a\x4a" + b"\x08"
            + b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" + b"\x00")
_QUIC_VN = _QUIC_VN + b"\x00" * (1200 - len(_QUIC_VN))
_UDP_PAYLOADS = {53: _DNS_QUERY, 5353: _DNS_QUERY, 161: _SNMP_GET,
                 443: _QUIC_VN, 853: _QUIC_VN}


def probe_tcp(host, port, timeout=2.0, retries=1):
    """open / closed / filtered / unreachable / unresolved for one TCP port.
    Unprivileged connect(). Accuracy notes (the states feed BLOCKED vs NO-SERVICE):
      - open       : the 3-way handshake completed.
      - closed     : a RST (refused / reset) — the host is up, nothing is
                     listening; this is NOT a control block.
      - filtered   : no response at all (silently dropped). A single dropped SYN
                     on a lossy/WAN path is retried once before we call it
                     filtered, so a one-off loss isn't a false BLOCKED.
      - unreachable: ICMP host/net-unreachable or admin-prohibited (a reject /
                     no route) — usually a boundary block.
    """
    last = "filtered"
    for _ in range(max(1, retries + 1)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return "open"
        except (socket.timeout, TimeoutError):
            last = "filtered"            # no response — retry once to confirm
            continue
        except ConnectionRefusedError:
            return "closed"              # RST — host up, nothing listening
        except ConnectionResetError:
            return "closed"              # RST mid-handshake — refused, not a block
        except socket.gaierror:
            return "unresolved"          # name/DNS did not resolve
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                return "closed"
            return "unreachable"         # no route / unreachable / admin-prohibited
    return last                          # timed out on every attempt -> filtered


def probe_udp(host, port, timeout=2.0):
    """Best-effort UDP (no handshake, so limited): open (a reply — including to a
    protocol-aware DNS probe) / closed (ICMP port-unreachable, reliably surfaced
    via a CONNECTED socket) / open|filtered (no reply — the common ambiguous
    case) / unreachable / unresolved. IPv4 and IPv6 (family from getaddrinfo)."""
    try:
        info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror:
        return "unresolved"
    except OSError:
        return "unreachable"
    if not info:
        return "unresolved"
    fam, _st, _pr, _cn, sa = info[0]
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # connect() so the kernel delivers ICMP port-unreachable to THIS socket
        # (an unconnected UDP socket usually won't see it -> false "open|filtered").
        s.connect(sa)
        s.send(_UDP_PAYLOADS.get(port, b""))
        try:
            s.recv(4096)
            return "open"                # something answered
        except socket.timeout:
            return "open|filtered"       # silent — can't tell open from filtered
        except ConnectionRefusedError:
            return "closed"              # ICMP port-unreachable came back
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "unreachable"
    finally:
        s.close()


def probe_icmp(host, timeout=3.0):
    """Best-effort ICMP reachability via the system ping (cross-OS flag: -n on
    Windows, -c elsewhere). Sends TWO echo requests — 'up' if EITHER replies —
    so a single dropped packet on a lossy/WAN path isn't a false 'down'.
    up / down/filtered / no-ping / unknown."""
    if shutil.which("ping") is None:
        return "no-ping"
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        p = subprocess.run(["ping", count_flag, "2", host],
                           capture_output=True, text=True, timeout=timeout + 4,
                           stdin=subprocess.DEVNULL)
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


def _cloud_port_map(target):
    """The cloud SMB/RPC alternate-port map for a target, if it's registered as a
    NAT'd cloud target (modules/_portpatch.py: e.g. {445:4445, 135:1135}). The GUI
    'Cloud target' tick and the CLI register these, so recon probes the forwarded
    ports the AD modules will actually hit — not the dead raw 445/135."""
    try:
        from modules import _portpatch
        return dict(_portpatch.CUSTOM_PORT_TARGETS.get(target) or {})
    except Exception:
        return {}


def reachability(target, modules, timeout=2.0, workers=32):
    """Probe the port(s) each module targets (tcp connect / best-effort udp /
    icmp ping), CONCURRENTLY (each distinct (proto,port) once). Returns {target,
    probes:[[proto,port,status]...], modules:[{id,name,probes,reachable,category,
    notes}]}. category is suggested|unreachable|indeterminate|noport. Advisory.

    For a cloud target with NAT'd SMB/RPC (see _cloud_port_map), a tcp port that is
    forwarded (445/135) is probed at its ALTERNATE (4445/1135) so reachability
    reflects where the service really is."""
    from concurrent.futures import ThreadPoolExecutor

    pmap = _cloud_port_map(target)

    def eff(proto, port):
        # only tcp SMB/RPC are NAT-forwarded; everything else is unchanged
        return pmap[port] if (proto == "tcp" and port in pmap) else port

    # collect the distinct probes needed across all modules, then run them in
    # parallel so filtered ports (each costing a full timeout) don't serialise.
    keys = []
    seen = set()
    for m in modules:
        for spec in m.META.get("ports", []):
            proto, port = spec if isinstance(spec, (list, tuple)) else ("tcp", spec)
            key = (proto, eff(proto, port))
            if key not in seen:
                seen.add(key)
                keys.append(key)

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
        notes = []
        for spec in meta.get("ports", []):
            proto, port = spec if isinstance(spec, (list, tuple)) else ("tcp", spec)
            ep = eff(proto, port)
            probes.append([proto, ep, cache.get((proto, ep), "unknown")])
            if ep != port:
                notes.append(f"cloud NAT: {proto}/{port}->{ep}")
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
                        "reachable": reachable, "category": category, "notes": notes})
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
        # seconds to wait BEFORE each run_last module (brute/DoS) so a rate-limit
        # they trigger has time to clear between them. 0 = off. Env HARNESS_COOLDOWN.
        try:
            self.cooldown = float(os.environ.get("HARNESS_COOLDOWN", "0") or 0)
        except ValueError:
            self.cooldown = 0.0
        # How long to WAIT for an IPS quarantine / source-blacklist to clear before
        # giving up and marking the rest INCONCLUSIVE. 0 = use the default
        # (max(30s, cooldown)). Set it higher than cooldown to sleep longer for a
        # ban to release without also lengthening the per-module cooldown. Env
        # HARNESS_WAIT_UNBLOCK / CLI --wait-unblock.
        try:
            self.wait_unblock = float(os.environ.get("HARNESS_WAIT_UNBLOCK", "0") or 0)
        except ValueError:
            self.wait_unblock = 0.0

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
        meta = m.META if hasattr(m, "META") else {}
        mid = meta.get("id", "?")
        # A module may declare its OWN longer watchdog via META["hard_timeout_s"]
        # (e.g. a time-spread stealth scan that deliberately runs for many minutes);
        # self.module_hard_timeout (test/override) still wins when set.
        cap = (self.module_hard_timeout or meta.get("hard_timeout_s")
               or ((self.ctx.timeout or DEFAULT_TIMEOUT) + 60))
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

    def _detection(self, meta, raw):
        """Return (source, note) if this attack — which PASSED — was flagged by
        the blue team, else None. Sources: the operator detections file (keyed by
        attack id), or a module self-reporting via META['detected_regex']."""
        det = getattr(self, "_detections", {}).get(meta["id"])
        if det is not None:
            return (det.get("source") or "detections file",
                    det.get("note") or det.get("source") or "alerted by blue team")
        if _match(raw, meta.get("detected_regex")):
            return ("module", "module self-reported a detection signal")
        return None

    def run(self, modules, iterations, ev, skip_unready=True, recon=True,
            mode="blackbox", site_id=None):
        def log(msg):
            try:
                self.on_log(msg)
            except Exception:
                pass
            ev.log(msg)

        # Assessment posture (recorded + announced; execution is identical — the
        # operator sets the SD-WAN to allow-all for a white-box baseline run).
        self._mode = "whitebox" if str(mode).lower().startswith("w") else "blackbox"

        # Blue-team detections (operator-supplied) so a passed attack can be
        # scored DETECTED (passed but alerted) vs a silent finding.
        self._detections = load_detections()

        # Contamination guard state (see _flag_if_blacklisted): a "canary" port the
        # source can reach at the start; if it later goes unreachable, the boundary
        # has blacklisted/quarantined the source and subsequent BLOCKEDs are suspect.
        import threading as _th
        self._canary = None
        self._blacklisted = False
        self._bl_lock = _th.Lock()

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

        path = "dual-path (baseline + appliance)" if self.dual else "single-target"
        banner = ("WHITEBOX (allow-all baseline — attacks SHOULD pass; confirms "
                  "the attack/service works)" if self._mode == "whitebox"
                  else "BLACKBOX (through the SD-WAN as-is — what gets blocked)")
        ev.meta["mode"] = self._mode
        # Self-describing run provenance (so summary.json/INDEX need no outside
        # context to diff runs): what was hit, from where, with which engine build.
        ev.meta["target_ip"] = self.target_ip
        if self.dual:
            ev.meta["appliance_ip"] = self.appliance_ip
        ev.meta["module_count"] = len(modules)
        ev.meta["harness_version"] = VERSION
        ev.meta["engine_version"] = _engine_version()
        # Site ID: an operator-supplied engagement/site tag recorded in the
        # evidence meta (and echoed by the CLI/GUI headers + report).
        site = site_id or os.environ.get("HARNESS_SITE_ID") or ""
        if site:
            ev.meta["site_id"] = site
        log("=" * 60)
        log("Harness v" + VERSION + (f" ({ev.meta['engine_version']})"
            if ev.meta.get("engine_version") else ""))
        log(f"MODE: {banner}")
        if site:
            log(f"SITE ID: {site}")
        log("=" * 60)
        log(f"Path: {path}")
        log(f"Target: {self.target_ip} ({areason})")
        log(f"Evidence dir: {ev.root}")
        if getattr(self.ctx, "allow_active", False):
            log("ACTIVE-ESTABLISHMENT: ON — live modules may build real tunnels / "
                "SOCKS pivots / DNS tunnels / exfil to your configured infra "
                "(ensure this is inside the authorised window).")
        else:
            log("ACTIVE-ESTABLISHMENT: OFF — live modules run in non-destructive "
                "indicator mode only (pass --active to enable).")
        if getattr(self.ctx, "source_ip", None):
            # A source IP that isn't a local interface address can't be bound to;
            # bind_source() swallows the failure so a module still works on the
            # default route, which means a typo'd/NAT address silently does
            # NOTHING. Test it up front and say so, instead of logging it as taken.
            if source_ip_bindable(self.ctx.source_ip):
                log(f"Source IP (egress bind): {self.ctx.source_ip}")
            else:
                log(f"[WARN] Source IP {self.ctx.source_ip} is NOT a bindable local "
                    "address — egress bind will be IGNORED and the OS default route "
                    "used. Use an IP that exists on a local interface (check `ip addr`).")
                # Make that promise TRUE for every module, not just the socket ones.
                # bind_source() already swallows a bad bind, but curl-based modules
                # pass `--interface <ip>` and would HARD-FAIL ("curl: (45) Failed
                # binding local address") — which previously made e.g. doh_multi
                # report NO-SERVICE while doh_bypass (no bind) scored SUCCESS on the
                # SAME egress path. Clearing it here keeps those verdicts consistent.
                self.ctx.source_ip = None
        # record the EFFECTIVE egress source (after the bindable check above may
        # have cleared an unusable one), so the evidence reflects what actually ran.
        ev.meta["source_ip"] = getattr(self.ctx, "source_ip", None) or ""
        if self._detections:
            log(f"Blue-team detections loaded: {len(self._detections)} "
                "attack id(s) will score DETECTED if they pass.")

        # ----- Preflight: verify tools/privileges BEFORE executing anything ---
        # ALWAYS runs first, every run (GUI + CLI), to confirm each module's
        # prerequisites (tools / python-libs / privilege / OS) are met. Stored in
        # the evidence meta so the preflight state is in summary.json too (not only
        # the human lines in run.log).
        pf = preflight(modules)
        ev.meta["preflight"] = pf
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
            if r.get("missing_py"):
                reasons.append("python import fails: " + ", ".join(r["missing_py"]))
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
                # pick a CANARY: a benign port that is OPEN now, so a later drop in
                # its reachability means the SOURCE got blacklisted (not that an
                # attack's own control fired). Prefer SSH/HTTP/HTTPS, else any open
                # tcp, else ICMP-up.
                opens = [(proto, port) for proto, port, st in rc["probes"]
                         if proto == "tcp" and st == "open"]
                pref = next((pp for p in (22, 80, 443, 8080, 21, 389) for pp in opens if pp[1] == p), None)
                if pref or opens:
                    self._canary = pref or opens[0]
                elif any(proto == "icmp" and st == "up" for proto, _p, st in rc["probes"]):
                    self._canary = ("icmp", None)
                if self._canary:
                    log(f"  canary (contamination guard): {self._canary[1] or 'icmp'}"
                        f"/{self._canary[0]} reachable — a later drop flags a source blacklist.")
            except Exception as e:
                log(f"[WARN] recon skipped (non-fatal): {e}")
        else:
            log("[WARN] recon DISABLED (--no-recon): port/service reachability is NOT "
                "verified, so BLOCKED vs NO-SERVICE can be misattributed. Prefer running "
                "with recon so we never assume a port is open.")

        # ----- Boundary port policy — evaluated BEFORE scanning (static/offline,
        # always runs) so a BLOCKED on a policy-DENIED port is attributed to the
        # SEGMENTATION boundary, not the IPS/WAF. Stored in meta + used by the
        # verdict annotation in _process_module. We do NOT assume reachability:
        # recon above checks the live port/service state separately.
        self._port_policy = load_port_policy()
        self._pol_by_id = {}
        allow_n = deny_n = egr_n = 0
        for m in modules:
            mp = module_policy(m.META, self._port_policy)
            self._pol_by_id[m.META["id"]] = mp
            if mp["outcome"] == "allowed":
                allow_n += 1
            elif mp["outcome"] == "blocked":
                deny_n += 1
            else:
                egr_n += 1
        ev.meta["port_policy"] = {
            "name": self._port_policy["name"],
            "allowed": allow_n, "blocked_by_policy": deny_n, "egress": egr_n,
            "modules": {mid: {"outcome": v["outcome"],
                              "ports": [f"{p}/{pt}:{st}" for p, pt, st in v["ports"]]}
                        for mid, v in self._pol_by_id.items()},
        }
        log(f"Port policy [{self._port_policy['name']}] (checked pre-scan): "
            f"{allow_n} on ALLOWED ports (reach the boundary → IPS/WAF is the control "
            f"under test), {deny_n} on DENIED/unlisted ports (expected SEGMENTATION block, "
            f"not an IPS result), {egr_n} egress/ICMP (policy n/a).")
        _denied = [m.META["name"] for m in modules
                   if self._pol_by_id[m.META["id"]]["outcome"] == "blocked"]
        if _denied:
            log("  policy-denied (expect BLOCKED @ boundary): " + ", ".join(_denied))

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
        import sys
        import threading
        from concurrent.futures import ThreadPoolExecutor

        # Snapshot the REAL stdout so _restore_process_globals can repair it if an
        # in-process AD module is abandoned by the watchdog mid-`redirect_stdout`.
        real_stdout = sys.stdout
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
            # Between iterations: if a previous iteration's DoS/brute blacklisted
            # the source (canary down), DON'T grind out a whole iteration of false
            # SUSPECT BLOCKEDs. Wait for the ban to clear (re-probing the canary),
            # and if it recovers, clear the latch and continue clean; if it stays
            # banned past the window, stop the remaining iterations.
            if it > 1 and self._blacklisted and self._canary:
                if not self._await_unblacklist(log, f"iteration {it}"):
                    log("  [blacklist] source still banned after the wait — SKIPPING the "
                        "remaining iteration(s) so they don't fill the report with false "
                        "BLOCKEDs. Whitelist the tester source (or drop iterations to 1 / run "
                        "the DoS modules in a separate pass), then re-run.")
                    break
            log(f"\n=== Iteration: {it} ===")

            # Parallel-safe = concurrency requested, module is ready, and not a
            # module that must run alone or last. `serial` modules (DoS/brute/AD)
            # can't share a batch; `run_last`/`trips_ips` modules trip a blacklist
            # or an inline IPS signature that would quarantine the source, so they
            # must also run sequentially AT THE END (never early in a parallel
            # pool) — otherwise the ban they cause contaminates everything after.
            # Everything else (skips + all modules when conc==1) runs sequentially.
            def _defer_last(m):
                return bool(m.META.get("run_last") or m.META.get("trips_ips"))
            parallel, serial = [], []
            for m in modules:
                mid = m.META["id"]
                unready = skip_unready and mid not in ready_ids
                is_serial = bool(m.META.get("serial")) or _defer_last(m)
                if conc > 1 and not unready and not is_serial:
                    parallel.append(m)
                else:
                    serial.append(m)

            # Defer-last: a module whose SIDE EFFECT persists and would contaminate
            # OTHER modules' verdicts — brute-force (trips an IP blacklist), DoS
            # floods (trip anti-DoS rate-limits), and IPS-signature attacks
            # (log4shell/struts2/web_ips_sigs/apache_41773/doh — an inline NGAF/NGFW
            # blacklists the source on the hit). Sort them to the very end of the
            # serial batch (which itself runs after the parallel batch) so the quiet
            # attacks all get a clean, uncontaminated test first; a ban they trigger
            # then only affects the recovery logic below, not earlier verdicts.
            # Stable sort: everything else keeps its order.
            serial.sort(key=_defer_last)
            if any(_defer_last(m) for m in serial):
                lastnames = ", ".join(m.META["name"] for m in serial if _defer_last(m))
                log(f"  (deferring to run LAST so a triggered blacklist / IPS-signature ban "
                    f"doesn't contaminate other results: {lastnames})")

            if parallel:
                log(f"  running {len(parallel)} module(s) with {conc} workers")
                with ThreadPoolExecutor(max_workers=min(conc, len(parallel))) as ex:
                    list(ex.map(lambda mm: self._process_module(
                        mm, it, skip_unready, ready_ids, pf_by_id, recon_by_id,
                        ev, log, bump), parallel))
                self._restore_process_globals(real_stdout)
            for i, m in enumerate(serial):
                if self._stop:
                    break
                # Mid-run quarantine recovery: if an earlier module tripped the
                # appliance and the source got blacklisted (canary down), DON'T
                # grind out false BLOCKEDs on the rest — wait for the ban to clear
                # before this module. If it recovers, the latch is cleared and we
                # continue clean; if it stays banned past the window, record this
                # and every remaining module as INCONCLUSIVE (not tested — the ban,
                # not a per-attack control) and stop the batch.
                if self._blacklisted and self._canary and not self._stop:
                    if not self._await_unblacklist(log, m.META["name"]):
                        log("  [blacklist] source still in IPS quarantine — recording the "
                            f"remaining {len(serial) - i} module(s) as INCONCLUSIVE (not tested) "
                            "instead of false BLOCKEDs. Whitelist the tester source on the "
                            "appliance (or wait for the quarantine to expire), then re-run.")
                        for rem in serial[i:]:
                            if self._stop:
                                break
                            self._record_untested(
                                rem, it, ev, log, bump, recon_by_id,
                                reason="source in IPS quarantine (canary unreachable) when this "
                                       "attack was due — not tested")
                        break
                # cooldown before each defer-last (brute/DoS/IPS-signature) module
                # so a rate-limit/ban it triggers has time to clear before the next.
                if self.cooldown and _defer_last(m) and not self._stop:
                    log(f"  (cooldown {self.cooldown:.0f}s before {m.META['name']} — "
                        "let any triggered rate-limit / IPS ban clear)")
                    _slept = 0.0
                    while _slept < self.cooldown and not self._stop:
                        time.sleep(min(1.0, self.cooldown - _slept))
                        _slept += 1.0
                self._process_module(m, it, skip_unready, ready_ids, pf_by_id,
                                     recon_by_id, ev, log, bump)
                # Defensive: repair process-global state after EACH serial module,
                # so an abandoned (hung) in-process AD module that never ran its
                # finally can't leave socket.connect patched / stdout redirected
                # and corrupt every later module.
                self._restore_process_globals(real_stdout)

    def _restore_process_globals(self, real_stdout):
        """Undo any leftover _portpatch socket.connect monkeypatch and stdout
        redirect. A no-op when the module cleaned up normally (the common case);
        the repair only matters when a module was abandoned by the watchdog
        mid-run (its `finally` never executed)."""
        try:
            from modules import _portpatch
            _portpatch.remove()
        except Exception:
            pass
        try:
            import sys
            if real_stdout is not None and sys.stdout is not real_stdout:
                sys.stdout = real_stdout
        except Exception:
            pass

    def _await_unblacklist(self, log, where):
        """Wait for a blacklisted source to be let back in, re-probing the canary.
        On recovery clear the latch and return True; otherwise return False.
        Shared by the between-iterations guard and the mid-run (per-module)
        quarantine recovery. The wait window is --wait-unblock/HARNESS_WAIT_UNBLOCK
        when set, else max(30s, cooldown)."""
        if not (self._blacklisted and self._canary):
            return True
        wait = self.wait_unblock if (getattr(self, "wait_unblock", 0) or 0) > 0 \
            else max(30.0, self.cooldown or 0.0)
        log(f"  [blacklist] source appears quarantined — waiting up to {wait:.0f}s for the "
            f"canary {self._canary[1] or 'icmp'}/{self._canary[0]} to recover before {where} "
            "(whitelist the tester source on the appliance to avoid this).")
        waited = 0.0
        while waited < wait and not self._stop:
            if self._canary_reachable():
                with self._bl_lock:
                    self._blacklisted = False
                log("  [blacklist] canary recovered — latch cleared, continuing clean.")
                return True
            time.sleep(min(5.0, wait - waited))
            waited += 5.0
        return False

    def _record_untested(self, m, it, ev, log, bump, recon_by_id, reason):
        """Record a module as INCONCLUSIVE (couldn't be fairly tested because the
        source was in IPS quarantine at the time) through the normal result path,
        so it shows in the live status, evidence, and summary like any verdict —
        but is never mistaken for a per-attack BLOCKED (control worked)."""
        meta = m.META
        b = "INCONCLUSIVE"
        verdict = (f"INCONCLUSIVE — {reason}. Whitelist/exempt the tester source on the "
                   "appliance (or wait for the quarantine to expire), then re-run "
                   "(`cli.py --suspect <evidence_dir>` lists what to repeat).")
        log(f"  [{meta['category']}] {meta['name']}")
        log(f"     target: [{b}]  -> {verdict}")
        self.on_status(meta["id"], meta["name"], it, b, verdict)
        self._record(ev, it, meta, b, "-", verdict, recon_by_id or {})
        bump()

    def _canary_reachable(self):
        """Is the canary port still reachable from the source? (quick probe)."""
        if not self._canary:
            return None
        proto, port = self._canary
        try:
            if proto == "tcp":
                return probe_tcp(self.target_ip, port, timeout=2, retries=0) == "open"
            if proto == "icmp":
                return probe_icmp(self.target_ip) == "up"
        except Exception:
            return None
        return None

    def _flag_if_blacklisted(self, verdict, log):
        """Called on a BLOCKED verdict: confirm the source can still reach the
        canary. If not, the boundary has BLACKLISTED/quarantined the source, so
        this BLOCKED (and later ones) may be fallout, not a per-attack control.
        Latches once and annotates the verdict so the operator isn't misled."""
        if not self._canary:
            return verdict
        # Fast path: already latched → just tag (no probe). Checked under the lock.
        with self._bl_lock:
            latched = self._blacklisted
        if not latched:
            # Probe the canary OUTSIDE the lock — it's a ~2s TCP connect (or ~7s
            # ping). Holding the lock across it would serialize every parallel
            # worker's BLOCKED behind this probe (N BLOCKEDs -> N x up to 7s).
            unreachable = self._canary_reachable() is False
            if unreachable:
                with self._bl_lock:
                    first = not self._blacklisted
                    self._blacklisted = True
                if first:
                    log("[WARN] SOURCE APPEARS BLACKLISTED by the boundary — the canary "
                        f"{self._canary[1] or 'icmp'}/{self._canary[0]} (reachable at start) "
                        "is now unreachable. BLOCKED/filtered verdicts from here are SUSPECT "
                        "(the ban, not per-attack controls). Standard fix: whitelist/exempt "
                        "the tester source IP from IPS blacklisting for the test window, then "
                        "re-run; or wait for the quarantine to expire.")
        with self._bl_lock:
            latched = self._blacklisted
        if latched:
            return verdict + "  [SUSPECT: source appears blacklisted — this BLOCKED " \
                             "may be the ban, not this attack's own control]"
        return verdict

    def _process_module(self, m, it, skip_unready, ready_ids, pf_by_id,
                        recon_by_id, ev, log, bump):
        """Run (or skip) one module for one iteration and record the result.
        Safe to call from worker threads (Evidence is locked, callbacks wrapped).

        Exception boundary: `m.run()` is already crash-wrapped in _safe_module_run,
        but the SURROUNDING classify/recon/record code could also raise on odd
        input. If it does, record this module as NO-RESULT and keep going — one bad
        module must never abort the rest of the run (CLAUDE.md guardrail)."""
        if self._stop:
            return
        meta = m.META
        try:
            self._process_module_inner(m, it, skip_unready, ready_ids, pf_by_id,
                                       recon_by_id, ev, log, bump)
        except Exception as e:
            hint = f"{e.__class__.__name__}: {e}"
            verdict = (f"engine error while processing this module ({hint}) — not a "
                       "control result; the run continues")
            for fn in (lambda: log(f"     target: [NO-RESULT]  -> {verdict}"),
                       lambda: self.on_status(meta["id"], meta["name"], it, "NO-RESULT", verdict),
                       lambda: self._record(ev, it, meta, "NO-RESULT", "-", verdict,
                                            recon_by_id, output=""),
                       bump):
                try:
                    fn()
                except Exception:
                    pass

    def _process_module_inner(self, m, it, skip_unready, ready_ids, pf_by_id,
                              recon_by_id, ev, log, bump):
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
            if r.get("missing_py"):
                bits.append("python import fails: " + ", ".join(r["missing_py"]))
            if not r["priv_ok"]:
                bits.append("needs root/admin")
            if not r.get("os_ok", True):
                bits.append(f"not supported on {platform.system()}")
            verdict = "PREREQ-MISSING — skipped (" + "; ".join(bits) + ")"
            b, a = "PREREQ-MISSING", "-"
            log(f"     target: [{b}]  -> {verdict}")
            self.on_status(meta["id"], meta["name"], it, b, verdict)
            self._record(ev, it, meta, b, a, verdict, recon_by_id, output="")
            bump()
            return

        _t0 = time.time()
        target_raw = self._safe_module_run(m, self.target_ip)
        duration = round(time.time() - _t0, 2)   # local: thread-safe under parallel workers
        ev.save_run(it, meta["id"], "target", target_raw)
        self.on_output(meta["id"], meta["name"], it, target_raw)
        detected_source = ""
        output_for_record = target_raw

        if self.dual:
            app_raw = self._safe_module_run(m, self.appliance_ip)
            ev.save_run(it, meta["id"], "through-appliance", app_raw)
            b, a, verdict = classify(meta, target_raw, app_raw)
            if a == "SUCCESS":
                det = self._detection(meta, app_raw)
                if det and _detection_is_real(det[1]):
                    a, detected_source = "DETECTED", det[0]
                    verdict = (f"attack passed the appliance but the appliance/SOC "
                               f"flagged it ({det[1]}) — {_detection_phrasing(det[1])}")
                elif det:
                    # session-log ALLOW through the appliance = policy reference /
                    # telemetry, not a detection — keep SUCCESS (the finding), annotate.
                    verdict += (f"  [note: appliance only session-logged + ALLOWED this flow "
                                f"({det[1]}) — policy REFERENCE / telemetry, not a detection]")
            # Parity with the single-target path: a BLOCKED through the appliance
            # gets the contamination-guard SUSPECT check, and a BLOCKED/NO-SERVICE
            # on a policy-DENIED port is attributed to SEGMENTATION, not the IPS/WAF.
            if a == "BLOCKED":
                verdict = self._flag_if_blacklisted(verdict, log)
            pol = getattr(self, "_pol_by_id", {}).get(meta["id"])
            if pol and pol["outcome"] == "blocked" and a in ("BLOCKED", "NO-SERVICE"):
                denied = ", ".join(f"{p}/{pt}" for p, pt, st in pol["ports"] if st != "allowed")
                pname = getattr(self, "_port_policy", {}).get("name", "port policy")
                verdict += (f"  [policy: {denied} denied by {pname} — expected SEGMENTATION "
                            "block, not an IPS/WAF result]")
            log(f"     baseline: [{b}]  appliance: [{a}]  -> {verdict}")
            output_for_record = target_raw + "\n\n--- through appliance ---\n\n" + app_raw
        else:
            ok = _match(target_raw, meta.get("success_regex"))
            authfail = _match(target_raw, AUTHFAIL_REGEX)
            refused = _match(target_raw, REFUSED_REGEX)
            # Anchor to REAL timeout markers — a bare "timeout" substring matches
            # benign text (a tool's `--timeout`, `timeout=5`, help output) and would
            # fabricate a BLOCKED (crediting the control for a non-event).
            timed_out = "[TIMEOUT]" in target_raw or _match(
                target_raw, r"timed out|connection timed out|operation timed out|recv timeout")
            blocked_out = _match(target_raw, meta.get("blocked_regex"))
            # a harness-internal fault (crash / watchdog-abandon / no-output /
            # command-parse / tool-not-found) — see _TOOL_FAIL_MARKER.
            tool_failed = _TOOL_FAIL_MARKER.search(target_raw) is not None
            # recon is the tie-breaker between "port closed (service absent)" and
            # "port filtered (dropped in transit — likely the SD-WAN)".
            rr = recon_by_id.get(meta["id"])
            tcp = [st for (proto, _p, st) in (rr["probes"] if rr else []) if proto == "tcp"]
            port_open = any(s == "open" for s in tcp)
            port_closed = bool(tcp) and not port_open and all(s == "closed" for s in tcp)
            port_filtered = bool(tcp) and not port_open and any(
                s in ("filtered", "unreachable", "unresolved") for s in tcp)

            # A module that deliberately did NOTHING (printed [SKIP] — e.g. an
            # active-establishment module with no config.json infra) must NEVER be
            # scored as a control win: nothing was ever sent. Check this BEFORE the
            # blocked/port branches — otherwise a "[SKIP] ... not configured" line
            # that happens to match a loose blocked_regex is mis-scored as BLOCKED
            # (fabricating "the control worked" when the test never ran).
            skipped = not ok and _SKIP_MARKER.search(target_raw) is not None
            if ok:
                det = self._detection(meta, target_raw)
                if det and _detection_is_real(det[1]):
                    b, detected_source = "DETECTED", det[0]
                    verdict = (f"attack passed the boundary but the appliance/SOC "
                               f"flagged it ({det[1]}) — {_detection_phrasing(det[1])}")
                else:
                    # The attack GOT THROUGH. A session-log ALLOW is the appliance's
                    # own policy REFERENCE (telemetry), NOT a detection — so this is
                    # a SUCCESS (the finding), with the reference attached so the
                    # operator still sees what the appliance logged without it being
                    # miscredited as "detection worked".
                    b, verdict = "SUCCESS", "attack succeeded against target (passed-undetected)"
                    if det:
                        verdict += (f" — note: the appliance only session-logged + ALLOWED "
                                    f"this flow ({det[1]}); that is a POLICY REFERENCE / "
                                    f"telemetry, not a detection and not a block. The attack "
                                    f"still got through — verify your SOC actually ALERTS on it.")
            elif authfail:
                b, verdict = "AUTH-FAILED", "credential error — fix credentials (HARNESS_DC_PASS), not a control result"
            elif skipped:
                hint = _error_hint(target_raw)
                b = "SKIPPED"
                verdict = ("module did nothing (not applicable / not configured) — "
                           + (hint or "see raw log") + "; NOT a control result")
            # A module self-declaring a missing LOCAL prerequisite at runtime (e.g.
            # kerberoast with a skewed clock and no faketime). Not a control result;
            # checked before the port/blocked branches so it can't be mis-scored as
            # BLOCKED/NO-SERVICE (which would fabricate "the control worked").
            elif _PREREQ_MARKER.search(target_raw):
                m = _PREREQ_MARKER.search(target_raw)
                reason = m.group(0).replace("[PREREQ-MISSING]", "").strip()
                b = "PREREQ-MISSING"
                verdict = ("skipped — " + (reason or "a runtime prerequisite is missing")
                           + "; NOT a control result (fix the prerequisite and re-run)")
            # A module that ran but legitimately CANNOT decide (declares its own
            # reason). Surfaces the reason instead of a mute NO-RESULT; authoritative
            # about its own run, like [SKIP], so it precedes the recon-inferred states.
            elif _INCONCLUSIVE_MARKER.search(target_raw):
                m = _INCONCLUSIVE_MARKER.search(target_raw)
                reason = m.group(0).replace("[INCONCLUSIVE]", "").strip()
                b = "INCONCLUSIVE"
                verdict = "INCONCLUSIVE — " + (reason or "the test was indeterminate; review raw log")
            # CLOSED / refused -> the service isn't there; this is NOT a control win.
            # ...but only when the attack ports aren't actually OPEN. An exploit
            # whose ports are reachable can still print an incidental "Connection
            # refused" (e.g. a stray DNS/ancillary lookup); without the port_open
            # guard that stray line mislabels a reachable, hardened target as
            # NO-SERVICE and robs its own blocked_regex (e.g. noPac's
            # KDC_ERR_TGT_REVOKED) of the BLOCKED verdict it earned.
            elif port_closed or (refused and not timed_out and not port_filtered
                                 and not port_open):
                b = "NO-SERVICE"
                verdict = ("port closed / connection refused — the service isn't running "
                           "or isn't accessible on the target; NOT an SD-WAN block "
                           "(attack could not apply)")
            # TOOL-INTERNAL fault with NO network signal of its own -> NO-RESULT.
            # Must come BEFORE the port_filtered->BLOCKED branch: recon's filtered
            # port is a SEPARATE probe, and crediting a crashed/abandoned module's
            # BLOCKED to the control fabricates a "control worked" result the test
            # never produced. (A real network signal — refused/timeout/blocked_regex
            # — is handled by the branches around this one and keeps its verdict.)
            elif tool_failed and not (refused or timed_out or blocked_out):
                hint = _error_hint(target_raw)
                b = "NO-RESULT"
                verdict = (f"no result (tool fault, not a control result) — {hint}"
                           if hint else "no result — tool fault; review raw log")
            # FILTERED / dropped / timed out -> blocked in transit (likely the SD-WAN)
            elif port_filtered or timed_out:
                b = "BLOCKED"
                verdict = ("attack blocked — target port filtered / traffic dropped in "
                           "transit (SD-WAN / upstream edge (ISP/cloud) / host firewall — "
                           "confirm WHICH via the appliance/host logs, e.g. sangfor_ingest.py)")
            elif blocked_out:
                b = "BLOCKED"
                # A tool-reported rejection while the attack port is OPEN is a
                # REJECTION block (an explicit refusal — HTTP 4xx, RST, a KDC
                # error — not a silent network drop). From the attacker side this
                # could be an IN-PATH IPS/WAF (e.g. the SD-WAN's inline inspection
                # returning 403) OR the endpoint itself (a patch / host hardening /
                # local ACL, e.g. a patched DC answering noPac with
                # KDC_ERR_TGT_REVOKED). We CANNOT tell which from here — only the
                # appliance/host logs can — so we don't claim one over the other.
                # (Contrast the port_filtered/timed_out branch above: a SILENT
                # drop, which IS the segmentation/SD-WAN signature.)
                if port_open:
                    verdict = ("attack blocked by a REJECTION RESPONSE while the port "
                               "is open (explicit refusal — HTTP 4xx / RST / protocol "
                               "error, not a silent drop) — an in-path IPS/WAF (e.g. "
                               "the SD-WAN's inline inspection) OR host hardening/patch; "
                               "which one needs the appliance/host logs to confirm")
                else:
                    verdict = "attack blocked/unreachable (per tool output)"
            else:
                hint = _error_hint(target_raw)
                b = "NO-RESULT"
                verdict = f"no result — {hint}" if hint else "no result — review raw log"
            a = "-"
            # contamination guard: a BLOCKED could be THIS attack's control OR the
            # source having been blacklisted by an earlier attack. If the canary is
            # now unreachable, flag the verdict as suspect (don't report a false win).
            if b == "BLOCKED":
                verdict = self._flag_if_blacklisted(verdict, log)
            # Port-policy attribution: a BLOCKED/NO-SERVICE on a port the boundary
            # policy DENIES is EXPECTED segmentation, not an IPS/WAF result — label
            # it so the two aren't conflated (this is the control working by design).
            pol = getattr(self, "_pol_by_id", {}).get(meta["id"])
            if pol and pol["outcome"] == "blocked" and b in ("BLOCKED", "NO-SERVICE"):
                denied = ", ".join(f"{p}/{pt}" for p, pt, st in pol["ports"] if st != "allowed")
                pname = getattr(self, "_port_policy", {}).get("name", "port policy")
                verdict += (f"  [policy: {denied} denied by {pname} — expected SEGMENTATION "
                            "block, not an IPS/WAF result]")
            # Whitebox posture = allow-all baseline: it SHOULD pass. A BLOCKED/
            # NO-SERVICE here is anomalous and usually means the service is down or
            # an upstream (edge/host) filter dropped it — NOT the SD-WAN control
            # (there's nothing between source and target to credit in white-box).
            if getattr(self, "_mode", "blackbox") == "whitebox" and b in ("BLOCKED", "NO-SERVICE"):
                verdict += ("  [whitebox-anomaly: the allow-all baseline should PASS — likely "
                            "service-down / upstream-edge / host filter, not a control result]")
            log(f"     target: [{b}]  -> {verdict}")

        # Live status shows the meaningful verdict: in dual mode that is the
        # APPLIANCE result (SUCCESS/BLOCKED/NO-SERVICE/DETECTED), not the baseline
        # (which is only OK/AUTH-FAILED/FAIL). Single-target shows b as before.
        self.on_status(meta["id"], meta["name"], it, (a if self.dual else b), verdict)
        self._record(ev, it, meta, b, a, verdict, recon_by_id,
                     detected_source=detected_source, output=output_for_record,
                     duration=duration)
        bump()

    def _record(self, ev, it, meta, b, a, verdict, recon_by_id, detected_source="", output="", duration=0.0):
        ev.save_result(it, meta["id"], {
            "iteration": it,
            "mode": getattr(self, "_mode", "blackbox"),
            "category": meta["category"],
            "attack": meta["name"],
            "attack_id": meta["id"],
            "control_tested": meta.get("control", meta["category"]),
            "fix_location": meta.get("fix", ""),
            # BAS mappings — carried into evidence so results are standards-aligned
            "test_type": meta.get("test_type", ""),
            "family": meta.get("family", ""),
            # a2b = SDWAN/site -> DC (northbound) · b2a = DC -> SDWAN/out (reverse)
            "direction": meta.get("direction", "a2b"),
            # the target port(s) this module probes/attacks ("tcp/80"; egress/icmp = "")
            "ports": ", ".join(f"{pr}/{p}" if p is not None else str(pr)
                               for (pr, p) in (meta.get("ports") or [])),
            "mitre": meta.get("mitre", []),
            "cwe": meta.get("cwe", []),
            "cve": meta.get("cve", ""),
            "tactic": meta.get("tactic", ""),
            "duration_s": duration,
            "baseline_result": b,
            "appliance_result": a,
            # "passed" = the attack got through UNDETECTED (the finding). In dual
            # mode the finding is the APPLIANCE leg (a == SUCCESS); DETECTED is a
            # separate bucket, same as single-target where SUCCESS!=DETECTED. Was
            # always False in dual mode because b is only OK/AUTH-FAILED/FAIL.
            "passed": (a == "SUCCESS") if (self.dual and a not in (None, "-"))
                      else (b == "SUCCESS"),
            "verdict": verdict,
            "detected_source": detected_source,
            "target_ip": self.target_ip,
            "appliance_ip": self.appliance_ip if self.dual else None,
            # egress source bind (whitelisted-source tracking) + per-port recon
            # state + boundary port-policy outcome — so each row is self-describing.
            "source_ip": getattr(self.ctx, "source_ip", "") or "",
            "recon": ", ".join(
                f"{pr}/{p if p is not None else ''}:{st}"
                for (pr, p, st) in ((recon_by_id.get(meta["id"]) or {}).get("probes") or [])),
            "policy": (getattr(self, "_pol_by_id", {}).get(meta["id"], {}) or {}).get("outcome", ""),
            "reachability": recon_by_id.get(meta["id"]),
            "timestamp": datetime.now().isoformat(),
            # full raw tool output — result.json/summary.json keep it
            # complete; finalize() truncates only the summary.csv copy (a
            # cell this big breaks Excel's ~32k char/cell limit).
            "output": output,
        })
