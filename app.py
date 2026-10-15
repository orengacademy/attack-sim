#!/usr/bin/env python3
"""
app.py — WEB front-end for the Control Validation Harness (the 3rd way to drive
the SAME engine, alongside gui.py (Tkinter) and cli.py (headless)).

  python3 app.py                 # serves on 0.0.0.0:8080 (all interfaces)
  python3 app.py --host 127.0.0.1 --port 9000
  python3 app.py --token SECRET  # require ?token=SECRET (or X-Token header)

Pure Python standard library only (no Flask/etc.) — matches the engine's
stdlib-only ethos. A background thread runs core.Runner; the browser gets a live
Server-Sent-Events stream of log/status/progress, a modern dark BENTO dashboard,
and links to the run's evidence (report.html / summary.json / raw logs).

SECURITY: this exposes a control panel that launches REAL attacks. Binding to
0.0.0.0 makes it reachable by anyone on the network — keep it on a trusted lab
segment, use --host 127.0.0.1 if unsure, and/or set --token. The rules-of-
engagement gate still applies: a run is refused unless ROE is confirmed (the web
checkbox, or a durable --accept-roe / HARNESS_CONFIRM_ROE=1 opt-in).
"""
import argparse
import json
import mimetypes
import os
import queue
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import core
import loader
import index   # SQLite cross-run index (derived from evidence/; rebuildable)

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
STATIC = os.path.join(HERE, "static")   # dashboard CSS/JS (served at /static/*)
mimetypes.add_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx")
mimetypes.add_type("text/csv", ".csv")
mimetypes.add_type("text/css", ".css")          # deterministic: strict mode needs text/css
mimetypes.add_type("text/javascript", ".js")    # deterministic across platforms

MODULES = loader.discover()
MOD_BY_ID = {m.META["id"]: m for m in MODULES}
try:
    from modules import _portpatch as _pp
    _CLOUD_TARGETS = tuple(getattr(_pp, "CLOUD_TARGETS", ()))
except Exception:
    _CLOUD_TARGETS = ()

# one run at a time (the engine swaps process-global state — _portpatch monkey-
# patch, redirect_stdout — so concurrent runs would collide, same as the GUI).
RUNS = {}                      # run_id -> {q, done, runner, roots, error}
RUN_LOCK = threading.Lock()
TOKEN = None                   # set from --token

_VCOLOR = getattr(core.Evidence, "_V_COLOR", {})
_VORDER = getattr(core.Evidence, "_V_ORDER",
                  ["SUCCESS", "DETECTED", "BLOCKED", "NO-SERVICE", "AUTH-FAILED",
                   "NO-RESULT", "INCONCLUSIVE", "SKIPPED", "PREREQ-MISSING"])
# Plain-language meaning per verdict for the dashboard's verdict key (mirrors
# cli.py's _VERDICT_GLOSS so terminal and web read the same).
_VGLOSS = {
    "SUCCESS": "got through, undetected — the finding",
    "DETECTED": "got through but a signature/SOC alert fired — detection worked, prevention did not",
    "BLOCKED": "stopped in transit (dropped/filtered/rejected) — the control held",
    "NOT-VULNERABLE": "service reached but the target is hardened against the attack (key-only SSH, no default SNMP community, patched) — a defender win, not a finding",
    "NO-SERVICE": "port closed/refused — service absent, NOT a control block",
    "AUTH-FAILED": "credential error — fix creds, not a control result",
    "NO-RESULT": "no clear signal — review the raw log",
    "INCONCLUSIVE": "couldn't be decided (source quarantined, or an unobservable callback)",
    "SKIPPED": "module did nothing — not applicable / not configured",
    "PREREQ-MISSING": "skipped — missing tool / pylib / privilege / OS / runtime prereq",
}


# ---------------------------------------------------------------------------
# data helpers
# ---------------------------------------------------------------------------
def _ports_str(meta, target=None):
    # delegate to the shared core helper so CLI/GUI/web/evidence agree on the ports
    # format AND the cloud NAT mapping (tcp/445->4445 on a NAT'd target).
    return core.display_ports(meta, target)


# Per-module raw output is kept in the run's state so a results row can be clicked
# to view it, WITHOUT streaming megabytes over SSE (icmp_flood's flood dump alone
# is ~3MB). Cap what we hold in RAM; the full, authoritative raw is in evidence.
OUTPUT_CAP = 400_000


def _stash_output(st, key, raw):
    try:
        s = raw if isinstance(raw, str) else str(raw)
        if len(s) > OUTPUT_CAP:
            s = s[:OUTPUT_CAP] + "\n\n…[truncated for the viewer — full raw output is in this run's evidence dir]"
        st.setdefault("outputs", {})[key] = s
    except Exception:
        pass


def _module_json(m):
    me = m.META
    return {
        "id": me["id"], "name": me["name"], "category": me.get("category", ""),
        "mitre": me.get("mitre", []), "cwe": me.get("cwe", []),
        "cve": me.get("cve", ""),
        "tactic": me.get("tactic", ""), "family": me.get("family", ""),
        "direction": me.get("direction", "a2b"), "test_type": me.get("test_type", ""),
        "control": me.get("control", ""), "fix": me.get("fix", ""),
        "added": bool(me.get("added")), "needs_root": bool(me.get("needs_root")),
        "requires": me.get("requires", []), "ports": _ports_str(me),
        "serial": bool(me.get("serial")), "run_last": bool(me.get("run_last")),
        "active": bool(me.get("active")),
    }


def _bootstrap():
    mods = [_module_json(m) for m in MODULES]
    ids = [m["id"] for m in mods]
    presets = {
        "all": ids,
        "original": [m["id"] for m in mods if not m["added"]],
        "added": [m["id"] for m in mods if m["added"]],
        "attack_sim": [m["id"] for m in mods if m["test_type"] == "attack_sim"],
    }
    try:
        creds = core.load_credentials()
    except Exception:
        creds = {}
    try:
        mem = core.load_target_memory() or {}
        targets = sorted(mem.keys(),
                         key=lambda k: mem[k].get("last_used", "") if isinstance(mem[k], dict) else "",
                         reverse=True)
    except Exception:
        mem, targets = {}, []
    # Per-target saved config, so the web form prefills EVERYTHING for a target the
    # same way the GUI does: NAT ports, cloud flag, egress source, posture, site,
    # and that target's own creds (a Linux host and a Windows DC carry different
    # logins). This is the trusted-lab control panel (bound to a trusted segment /
    # --token), identical exposure to the creds the form already POSTs on a run.
    tcfg = {}
    for ip, v in (mem.items() if isinstance(mem, dict) else []):
        if not isinstance(v, dict):
            continue
        tcfg[ip] = {
            "cloud": bool(v.get("cloud")),
            "smb_port": v.get("smb_port") or 4445,
            "rpc_port": v.get("rpc_port") or 1135,
            "ssh_port": v.get("ssh_port") or 22,
            "source": v.get("source") or "",
            "site_id": v.get("site_id") or "",
            "mode": v.get("mode") or "blackbox",
            "domain": v.get("domain") or "", "dc_user": v.get("dc_user") or "",
            "dc_pass": v.get("dc_pass") or "", "ssh_user": v.get("ssh_user") or "",
            "ssh_pass": v.get("ssh_pass") or "",
        }
    try:
        policy = core.load_port_policy().get("name", "")
    except Exception:
        policy = ""
    return {
        "version": core.VERSION,
        "engine": getattr(core, "_engine_version", lambda: "")() if hasattr(core, "_engine_version") else "",
        "workers": core.RECOMMENDED_WORKERS,
        "roe": bool(core.roe_accepted()),
        "policy": policy,
        "creds_loaded": {k: bool(creds.get(k)) for k in
                         ("domain", "dc_user", "dc_pass", "ssh_user", "ssh_pass")},
        # actual global defaults (credentials.env / HARNESS_*) so the form prefills,
        # plus each target's own saved config for per-target prefill on selection.
        "creds": {k: creds.get(k, "") for k in
                  ("domain", "dc_user", "dc_pass", "ssh_user", "ssh_pass")},
        "target_config": tcfg,
        # Canonical cloud DCs (always NAT'd 4445/1135) — the UI forces net=cloud for
        # these so a run can't mislabel their transport; the engine forces it anyway.
        "cloud_targets": list(_CLOUD_TARGETS),
        "modules": mods, "presets": presets, "targets": targets,
        "verdict_order": _VORDER,
        "verdict_colors": {v: _VCOLOR.get(v, "#8b90a6") for v in _VORDER},
        "verdict_gloss": {v: _VGLOSS.get(v, "") for v in _VORDER},
        "categories": sorted({m["category"] for m in mods}),
    }


def _status_event(aid, name, it, b, v, target, posture=""):
    me = MOD_BY_ID.get(aid)
    meta = me.META if me else {}
    return {"type": "status", "id": aid, "name": name, "it": it,
            "verdict": b, "detail": v, "target": target, "posture": posture,
            "category": meta.get("category", ""),
            "mitre": ", ".join(meta.get("mitre", [])),
            "cwe": ", ".join(meta.get("cwe", [])),
            "direction": meta.get("direction", "a2b"),
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),   # per-module completion timestamp (date + time)
            "ports": _ports_str(meta, target) or "—"}


def _fmt_recon_web(s):
    """'None/icmp:up, 21/tcp:open, …' -> 'icmp · tcp 21 22 … · udp 161' (reachable only)."""
    import re
    tcp, udp, icmp = [], [], False
    for tok in s.split(","):
        m = re.match(r"\s*(\S+?)/(\w+):(\w+)", tok)
        if not m:
            continue
        port, proto, state = m.groups()
        if proto == "icmp" and state in ("up", "open"):
            icmp = True
        elif state == "open" and proto == "tcp":
            tcp.append(port)
        elif state == "open" and proto == "udp":
            udp.append(port)
    bits = []
    if icmp:
        bits.append("icmp")
    if tcp:
        bits.append("tcp " + " ".join(tcp))
    if udp:
        bits.append("udp " + " ".join(udp))
    return " · ".join(bits) or s


def _parse_setup(lines):
    """Parse the engine's one-time setup log (platform/preflight/recon/policy) into
    a structured dict the dashboard renders as 'command-center' bento cards. Defensive:
    missing fields come back '' / []. Mirrors the CLI's setup panel."""
    import re
    used = [False] * len(lines)

    def first(pat):
        for i, l in enumerate(lines):
            m = re.search(pat, l)
            if m:
                used[i] = True
                return m
        return None

    d = {}
    m = first(r"^Platform:\s*(.+)")
    if m:
        parts = [p.strip() for p in m.group(1).split("|")]
        d["platform"] = parts[0] if parts else ""
        rt = []
        for p in parts[1:]:
            p = p.replace("privilege:", "").replace("pkg mgr:", "").replace("Python", "py").strip()
            if p:
                rt.append(p)
        d["runtime"] = rt
    for key, pat in (("preflight", r"^Preflight:\s*(.+?)\.?$"), ("active", r"^ACTIVE-ESTABLISHMENT:\s*(\w+)"),
                     ("detections", r"^Blue-team detections loaded:\s*(\d+)"), ("evidence", r"^Evidence dir:\s*(.+)"),
                     ("source", r"^Source IP \(egress bind\):\s*(.+)"), ("canary", r"^\s*canary[^:]*:\s*(.+)")):
        m = first(pat)
        d[key] = m.group(1) if m else ""
    first(r"^Path:\s")
    m = first(r"^Recon \(reachability of ([^)]+)\):\s*(.+)")
    if m:
        d["recon_target"] = m.group(1)
        d["reachable"] = _fmt_recon_web(m.group(2))
    d["recon_disabled"] = bool(first(r"^\[WARN\] recon"))
    m = first(r"^\s*suggested[^:]*:\s*(.+)")
    d["suggested"] = [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []
    m = first(r"^\s*not reachable[^:]*:\s*(.+)")
    d["filtered"] = [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []
    m = first(r"^Port policy \[([^\]]+)\][^:]*:\s*(.+)")
    if m:
        d["policy_name"] = m.group(1)
        body = m.group(2)
        for k, pat in (("allowed", r"(\d+) on ALLOWED"), ("denied", r"(\d+) on DENIED"), ("na", r"(\d+) egress")):
            mm = re.search(pat, body)
            d["policy_" + k] = mm.group(1) if mm else ""
    m = first(r"^\s*policy-denied[^:]*:\s*(.+)")
    d["expect_block"] = [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []
    return d


# ---------------------------------------------------------------------------
# run orchestration (background thread -> per-run event queue -> SSE)
# ---------------------------------------------------------------------------
def _start_run(params):
    # ROE gate — identical policy to gui/cli: an explicit confirm or a durable opt-in.
    if not (params.get("confirm_roe") or core.roe_accepted()):
        return None, "Rules-of-engagement not confirmed (tick the ROE box)."
    # New per-target-row model: each row carries its own posture + net (cloud/
    # on-prem). Derive the target list from the rows (order-preserving, de-duped);
    # fall back to the legacy flat `targets` list for older API callers.
    rows = params.get("rows") or []
    if rows:
        targets, seen = [], set()
        for r in rows:
            ip = str((r or {}).get("target", "")).strip()
            if ip and ip not in seen:
                seen.add(ip); targets.append(ip)
    else:
        targets = [t.strip() for t in params.get("targets", []) if t.strip()]
    if not targets:
        return None, "No target given."
    for t in targets:
        ok, why = core.validate_target(t)
        if not ok:
            return None, f"{t}: {why}"
        allowed, areason = core.target_allowed(t)
        if not allowed:
            return None, f"{t}: {areason}"
    module_ids = [i for i in params.get("module_ids", []) if i in MOD_BY_ID]
    if not module_ids:
        return None, "No attacks selected."

    with RUN_LOCK:
        for st in RUNS.values():
            if not st["done"]:
                return None, "A run is already in progress — wait for it to finish or stop it."
        run_id = uuid.uuid4().hex[:12]
        st = {"q": queue.Queue(), "done": False, "runner": None,
              "roots": [], "error": None, "started": time.time(), "outputs": {},
              "current_root": None}
        RUNS[run_id] = st

    t = threading.Thread(target=_run_worker, args=(run_id, params, targets, module_ids), daemon=True)
    t.start()
    return run_id, None


def _run_worker(run_id, params, targets, module_ids):
    st = RUNS[run_id]
    q = st["q"]
    emit = q.put
    mods = [MOD_BY_ID[i] for i in module_ids]
    try:
        iters = max(1, int(params.get("iterations", 1) or 1))
    except (TypeError, ValueError):
        iters = 1
    try:
        workers = max(1, int(params.get("workers", core.RECOMMENDED_WORKERS) or 1))
    except (TypeError, ValueError):
        workers = core.RECOMMENDED_WORKERS
    try:
        wait_unblock = max(0.0, float(params.get("wait_unblock", 0) or 0))
    except (TypeError, ValueError):
        wait_unblock = 0.0
    try:
        ban_expiry = max(0.0, float(params.get("ban_expiry", 300) or 0))
    except (TypeError, ValueError):
        ban_expiry = 300.0
    try:
        auto_retry = max(0, int(params.get("auto_retry", 1) or 0))
    except (TypeError, ValueError):
        auto_retry = 1
    # Posture is a per-run REQUEST: explicit blackbox/whitebox forces one config
    # on every target; 'auto' (the default) runs each target by its OWN designated
    # profile from target memory — posture AND transport (cloud/NAT ports) AND
    # creds AND egress source — so a mixed batch (159.* whitebox+cloud, 10.38.98.14
    # blackbox+on-prem) just works from one IP list. The form fields are the
    # fallback for unknown targets and the explicit-override path.
    req_mode = str(params.get("mode") or "auto").strip().lower()
    auto = req_mode not in ("blackbox", "whitebox")
    site_id = (params.get("site_id") or "").strip() or None
    active = bool(params.get("active"))
    debug = bool(params.get("debug"))
    form_creds = {k: v for k, v in (params.get("creds") or {}).items() if v}
    form_source = (params.get("source") or "").strip() or None
    appliance = (params.get("appliance") or "").strip() or None   # dual-path 2nd leg
    form_cloud = bool(params.get("cloud"))

    def _int(v, default):
        try:
            return int(v)
        except (TypeError, ValueError):
            return default
    form_smb = _int(params.get("smb_port"), 4445)
    form_rpc = _int(params.get("rpc_port"), 1135)
    form_ssh = _int(params.get("ssh_port"), 22)
    _CRED_KEYS = ("domain", "dc_user", "dc_pass", "ssh_user", "ssh_pass")
    # Per-target rows from the redesigned UI: {target: {"posture","cloud"}}. When a
    # target has a row, its posture + net come straight from that row (explicit),
    # overriding the Auto/memory resolution below.
    row_by_target = {}
    for r in (params.get("rows") or []):
        ip = str((r or {}).get("target", "")).strip()
        if ip:
            row_by_target[ip] = r
    try:
        from modules import _portpatch
    except Exception:
        _portpatch = None

    emit({"type": "started", "run_id": run_id, "targets": targets,
          "mode": req_mode, "iterations": iters, "workers": workers,
          "count": len(mods), "site_id": site_id or "", "active": active})
    try:
        for ti, target in enumerate(targets, 1):
            # Resolve this target's FULL profile. In auto, pull each dimension from
            # the target's memory (fall back to the form for anything unset); in
            # explicit, the form applies to all targets.
            row = row_by_target.get(target)
            prof = core.recall_target(target) if (auto or row is not None) else {}
            if row is not None:
                # EXPLICIT per-row posture + net from the UI. Ports: the target's own
                # remembered NAT ports win, else the form's NAT defaults. Creds: a
                # target's OWN remembered cred wins per key, else the shared on-screen
                # creds — so one Administrator/NewPass123! set covers every DC row.
                rp = str(row.get("posture", "")).strip().lower()
                posture = ("whitebox" if rp.startswith("w")
                           else "blackbox" if rp.startswith("b")
                           else core.resolve_posture(target, "auto"))
                t_cloud = bool(row.get("cloud"))
                t_smb = _int(prof.get("smb_port"), form_smb)
                t_rpc = _int(prof.get("rpc_port"), form_rpc)
                t_ssh = _int(prof.get("ssh_port"), form_ssh)
                t_source = prof.get("source") or form_source
                t_creds = {k: (prof.get(k) or form_creds.get(k))
                           for k in _CRED_KEYS if (prof.get(k) or form_creds.get(k))}
            elif auto:
                posture = core.resolve_posture(target, req_mode)
                t_cloud = bool(prof.get("cloud"))
                t_smb = _int(prof.get("smb_port"), 4445)
                t_rpc = _int(prof.get("rpc_port"), 1135)
                t_ssh = _int(prof.get("ssh_port"), 22)
                t_source = prof.get("source") or form_source
                t_creds = {k: prof.get(k) for k in _CRED_KEYS if prof.get(k)} or form_creds
            else:
                posture = core.resolve_posture(target, req_mode)
                t_cloud, t_smb, t_rpc, t_ssh = form_cloud, form_smb, form_rpc, form_ssh
                t_source, t_creds = form_source, form_creds
            # Transport is TARGET-authoritative: a canonical cloud DC (159/167) is
            # ALWAYS NAT'd 4445/1135 and its mapping is never cleared; everything
            # else is on-prem 445/135 unless the row explicitly chose cloud. This
            # stops the AD modules being pointed at the dead raw 445/135 (-> BLOCKED).
            t_cloud, _tmap = core.apply_transport(target, t_cloud, t_ssh)
            if _tmap:
                t_smb, t_rpc = _tmap.get(445, t_smb), _tmap.get(135, t_rpc)
            emit({"type": "target", "index": ti, "total": len(targets), "target": target,
                  "posture": posture, "cloud": bool(t_cloud)})
            _setupbuf = {"buf": [], "done": False}

            def _onlog(m, _t=target, _sb=_setupbuf):
                line = str(m)
                emit({"type": "log", "line": line})   # full log still streams to the Live-log pane
                if _sb["done"]:
                    return
                st = line.strip()
                if st.startswith("=== Iteration"):
                    _sb["done"] = True
                    emit({"type": "setup", "target": _t, "data": _parse_setup(_sb["buf"])})
                elif st and not st.startswith(("=", "Harness v", "MODE:", "SITE ID:")):
                    _sb["buf"].append(st)

            runner = core.Runner(
                target, appliance,
                on_log=_onlog,
                on_progress=lambda c, t: emit({"type": "progress", "done": c, "total": t}),
                on_output=lambda aid, name, it, raw, _t=target: (
                    _stash_output(st, f"{_t}|{aid}|{it}", raw),
                    emit({"type": "output", "id": aid, "name": name, "it": it, "target": _t}))[-1],
                on_status=lambda aid, name, it, b, v, _t=target, _p=posture: emit(_status_event(aid, name, it, b, v, _t, _p)))
            st["runner"] = runner
            runner.concurrency = workers
            if wait_unblock > 0:
                runner.wait_unblock = wait_unblock
            runner.ban_expiry = ban_expiry
            runner.auto_retry = auto_retry
            runner.ctx.allow_active = active
            runner.ctx.debug = debug
            for k, v in t_creds.items():
                runner.ctx.creds[k] = v
            if t_source:
                runner.ctx.source_ip = t_source
            try:
                if row is not None or not auto:
                    # explicit per-row (or legacy explicit): persist the chosen
                    # posture + net + ports + creds so the next load prefills them.
                    core.remember_target(target, source=t_source, cloud=t_cloud,
                                         smb_port=(t_smb if t_cloud else None),
                                         rpc_port=(t_rpc if t_cloud else None),
                                         ssh_port=(t_ssh if t_cloud else None),
                                         mode=posture, site_id=site_id, **t_creds)
                else:
                    core.remember_target(target)   # Auto: touch last_used; don't clobber the profile
            except Exception:
                pass
            ev = core.Evidence(label=(target if len(targets) > 1 else None))
            # expose the in-flight evidence dir so /api/runs can show it as
            # "running…" instead of "no summary" (finalize writes the summaries
            # only when the run — incl. any source-blacklist wait — completes).
            st["current_root"] = os.path.relpath(ev.root, HERE)
            root = runner.run(mods, iters, ev, mode=posture, site_id=site_id)
            rel = os.path.relpath(root, HERE)
            st["current_root"] = None
            st["roots"].append({"target": target, "root": rel})
            emit({"type": "target_done", "target": target, "root": rel})
            if getattr(runner, "_stop", False):
                break
            if _portpatch is not None and t_cloud:
                _portpatch.CUSTOM_PORT_TARGETS.pop(target, None)
        emit({"type": "done", "roots": st["roots"]})
    except Exception as e:
        st["error"] = str(e)
        emit({"type": "error", "error": str(e)})
    finally:
        st["done"] = True


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "CVH-web"

    def log_message(self, *a):
        pass  # quiet

    # --- auth -----------------------------------------------------------
    def _authed(self, q):
        if not TOKEN:
            return True
        tok = (q.get("token", [None])[0]) or self.headers.get("X-Token")
        return tok == TOKEN

    # --- helpers --------------------------------------------------------
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text, code=200):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # never let a browser serve a stale cached copy of the dashboard — a
        # redesign should show on the next load, not after a manual hard-refresh.
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    # --- routing --------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path
        # Static UI assets (CSS/JS — client code, no secrets) are served BEFORE
        # the token gate, so the dashboard still styles + boots when --token is
        # set (a <link>/<script src> can't carry the ?token=/X-Token). The token
        # keeps guarding the /api/* + /evidence/* routes below.
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])
        if not self._authed(q):
            return self._json({"error": "unauthorized (missing/invalid token)"}, 401)
        if path in ("/", "/index.html"):
            return self._html(PAGE)
        if path == "/api/bootstrap":
            return self._json(_bootstrap())
        if path == "/api/runs":
            return self._json({"runs": _list_runs()})
        if path.startswith("/api/run/") and path.endswith("/stream"):
            return self._sse(path.split("/")[3])
        if path.startswith("/api/run/") and path.endswith("/output"):
            return self._run_output(path.split("/")[3], q)
        if path == "/api/query":
            return self._query(q)
        if path.startswith("/evidence/"):
            return self._serve_evidence(path[len("/evidence/"):])
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._authed(q):
            return self._json({"error": "unauthorized"}, 401)
        path = u.path
        if path == "/api/run":
            run_id, err = _start_run(self._body())
            if err:
                return self._json({"error": err}, 400)
            return self._json({"run_id": run_id})
        if path.startswith("/api/run/") and path.endswith("/stop"):
            st = RUNS.get(path.split("/")[3])
            if st and st.get("runner"):
                try:
                    st["runner"].stop()
                except Exception:
                    pass
                return self._json({"ok": True})
            return self._json({"error": "no such run"}, 404)
        if path == "/api/reindex":
            try:
                nr, nres = index.rebuild()
                return self._json({"ok": True, "runs": nr, "results": nres})
            except Exception as e:
                return self._json({"error": str(e)}, 500)
        return self._json({"error": "not found"}, 404)

    # --- cross-run history query (SQLite index over evidence/) ----------
    def _query(self, q):
        # build the index on first use if it's missing (derived + rebuildable).
        if not os.path.exists(index.DB_DEFAULT):
            try:
                index.rebuild()
            except Exception as e:
                return self._json({"error": "index build failed: %s" % e}, 500)
        one = lambda k: (q.get(k, [""])[0] or "").strip()
        filters = {c: one(c) for c in ("verdict", "target_ip", "site_id", "category",
                                       "attack_id", "test_type", "family", "mode")}
        try:
            rows = index.query(filters={k: v for k, v in filters.items() if v},
                               q=one("q") or None, limit=int(one("limit") or 500))
            return self._json({"rows": rows, "stats": index.stats()})
        except Exception as e:
            return self._json({"error": str(e)}, 500)

    # --- per-module raw output (for the clickable results row) ----------
    def _run_output(self, run_id, q):
        st = RUNS.get(run_id)
        if not st:
            return self._json({"error": "no such run"}, 404)
        key = "%s|%s|%s" % (q.get("target", [""])[0], q.get("id", [""])[0],
                            q.get("it", ["1"])[0])
        txt = (st.get("outputs") or {}).get(key)
        if txt is None:
            return self._json({"error": "no captured output for that row"}, 404)
        return self._json({"output": txt})

    # --- SSE ------------------------------------------------------------
    def _sse(self, run_id):
        st = RUNS.get(run_id)
        if not st:
            return self._json({"error": "no such run"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q = st["q"]
        try:
            while True:
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    if st["done"] and q.empty():
                        break
                    continue
                self.wfile.write(b"data: " + json.dumps(ev).encode() + b"\n\n")
                self.wfile.flush()
                if ev.get("type") in ("done", "error"):
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass

    # --- evidence file serving (read-only, traversal-guarded) -----------
    def _serve_static(self, rel):
        # Same realpath containment as _serve_evidence: resolve symlinks on both
        # sides and require the result to be STATIC itself or a descendant (the
        # trailing os.sep stops a sibling like `static_x` from prefix-matching).
        rel = rel.split("?")[0]
        base = os.path.realpath(STATIC)
        full = os.path.realpath(os.path.join(STATIC, rel))
        if full != base and not full.startswith(base + os.sep):
            return self._json({"error": "forbidden"}, 403)
        if not os.path.isfile(full):
            return self._json({"error": "not found"}, 404)
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            return self._json({"error": "unreadable"}, 500)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        # match PAGE: never serve a stale asset after a redesign (lab tool, no CDN).
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_evidence(self, rel):
        rel = rel.split("?")[0]
        # ONE path validator (no normpath-vs-realpath differential): resolve
        # symlinks on both sides and require the resolved path to be the evidence
        # dir itself or a descendant. The trailing os.sep is mandatory — without
        # it a sibling like `evidence_backup` would prefix-match `.../evidence`.
        base = os.path.realpath(EVID)
        full = os.path.realpath(os.path.join(EVID, rel))
        if full != base and not full.startswith(base + os.sep):
            return self._json({"error": "forbidden"}, 403)
        if os.path.isdir(full):
            try:
                items = sorted(os.listdir(full))
            except OSError:
                return self._json({"error": "not found"}, 404)
            return self._json({"dir": rel, "items": items})
        if not os.path.isfile(full):
            return self._json({"error": "not found"}, 404)
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            return self._json({"error": "unreadable"}, 500)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


_RUN_META_CACHE = {}   # path -> (summary.json mtime, extracted-meta dict)


def _run_meta(path):
    """Pull the self-describing provenance out of a run's summary.json meta:
    source -> destination, posture (white/black), transport (cloud/on-prem), site,
    finding count. Cached by summary.json mtime so re-listing is cheap even with
    hundreds of runs. Missing/old runs (no summary yet, or pre-dating the extra
    meta) just come back with blanks — the run is still listed, never dropped."""
    sp = os.path.join(path, "summary.json")
    try:
        mt = os.path.getmtime(sp)
    except OSError:
        return {}
    hit = _RUN_META_CACHE.get(path)
    if hit and hit[0] == mt:
        return hit[1]
    meta = {}
    try:
        with open(sp) as f:
            meta = (json.load(f) or {}).get("meta", {}) or {}
    except Exception:
        meta = {}
    cloud = meta.get("cloud")
    out = {"target": meta.get("target_ip", "") or "",
           "source": meta.get("source_ip", "") or "",
           "appliance": meta.get("appliance_ip", "") or "",
           "mode": (meta.get("mode") or "").lower(),
           "cloud": (bool(cloud) if cloud is not None else None),
           "site": meta.get("site_id", "") or "",
           "findings": meta.get("finding_count"),
           "verdicts": meta.get("verdicts") or {},
           "modules": meta.get("module_count")}
    _RUN_META_CACHE[path] = (mt, out)
    return out


def _list_runs(limit=None):
    """Every run/fleet evidence dir (newest first), each enriched with its
    source->destination / posture / transport provenance. `limit=None` returns
    ALL of them (the dashboard shows every run — none are dropped)."""
    out = []
    try:
        dirs = [n for n in os.listdir(EVID)
                if n.startswith(("run_", "fleet_")) and os.path.isdir(os.path.join(EVID, n))]
    except OSError:
        return out
    # sort by mtime desc so the newest run is first regardless of the two
    # evidence naming formats (DD-MM-HH-MM vs older ISO), which don't sort
    # consistently by name.
    dirs.sort(key=lambda n: os.path.getmtime(os.path.join(EVID, n)), reverse=True)
    # the in-flight run's evidence dir (one run at a time) has no summaries yet —
    # mark it so the UI shows "running…" rather than "no summary".
    active = set()
    with RUN_LOCK:
        for st in RUNS.values():
            if not st.get("done") and st.get("current_root"):
                active.add(os.path.basename(str(st["current_root"]).rstrip("/")))
    for name in (dirs if limit is None else dirs[:limit]):
        p = os.path.join(EVID, name)
        has = {f: os.path.isfile(os.path.join(p, f))
               for f in ("report.html", "summary.json", "summary.csv", "summary.xlsx",
                         "report.txt", "attack_navigator_layer.json")}
        m = _run_meta(p)
        # destination falls back to the "__<target>" suffix multi-target runs carry
        # in the dir name when the summary isn't written yet.
        dest = m.get("target") or (name.split("__", 1)[1] if "__" in name else "")
        out.append({"name": name, "mtime": os.path.getmtime(p), "files": has,
                    "active": name in active, "target": dest,
                    "source": m.get("source", ""), "appliance": m.get("appliance", ""),
                    "mode": m.get("mode", ""), "cloud": m.get("cloud"),
                    "site": m.get("site", ""), "findings": m.get("findings"),
                    "modules": m.get("modules")})
    return out


# ---------------------------------------------------------------------------
# the single-page dashboard (served as a plain string — no interpolation)
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Control Validation Harness</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%235fe3e8' stroke-width='1.6'%3E%3Ccircle cx='12' cy='12' r='7.5'/%3E%3Cpath d='M12 1.8V6M12 18v4.2M1.8 12H6M18 12h4.2'/%3E%3Ccircle cx='12' cy='12' r='1.9' fill='%235fe3e8' stroke='none'/%3E%3C/svg%3E">
<link rel=preconnect href="https://fonts.googleapis.com">
<link rel=preconnect href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel=stylesheet>
<link rel=stylesheet href="static/app.css">
</head>
<body><div class=shell>

<header class=topbar>
 <div class=brand>
  <svg class=mark viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
   <circle cx="12" cy="12" r="7.5"></circle>
   <path d="M12 1.5V6M12 18v4.5M1.5 12H6M18 12h4.5"></path>
   <circle cx="12" cy="12" r="1.8" fill="currentColor" stroke="none"></circle>
  </svg>
  <div>
   <div class=title><span class=wordmark>ATTACK &middot; SIM</span><span class=tagline>Control Validation Harness</span></div>
   <div class=sub id=subline><span>connecting…</span></div>
  </div>
 </div>
 <div class=cmd>
  <label class=switch id=roeswitch><input type=checkbox id=roe aria-label="Rules of engagement confirmed"><span class=track></span><span>Rules of engagement</span></label>
  <button class="btn stop" id=stopbtn disabled>Stop</button>
  <button class="btn run" id=runbtn>Run battery</button>
 </div>
</header>

<main class=console>
 <!-- command rail -->
 <aside class=rail>
  <div class=group>
   <div class=ghead><h2>Target &amp; scope</h2><span class=rule></span></div>
   <div class=field>
    <div class=tgthead><label>Targets</label><button type=button id=addtgt class=addtgt>+ add target</button></div>
    <div class=targetrows id=targetRows></div>
    <div class=tgthint>each row picks its own <b>posture</b> — <span class="tk b">black</span>/<span class="tk w">white</span> — and <b>net</b> — on-prem (SMB/RPC direct <b>445/135</b>) / cloud (NAT'd <b>4445/1135</b>)</div>
   </div>
   <div class=rowf>
    <div class=field><label for=iters>Iterations</label><input id=iters type=number min=1 max=20 value=1></div>
    <div class=field><label for=workers>Workers</label><input id=workers type=number min=1 max=16 value=4></div>
   </div>
   <div class=subgroup>
    <div class=subhead>Source-blacklist recovery</div>
    <div class=rowf>
     <div class=field><label for=wait>Wait s</label><input id=wait type=number min=0 value=0></div>
     <div class=field><label for=banexp>Ban s</label><input id=banexp type=number min=0 value=300></div>
     <div class=field><label for=autoretry>Retry</label><input id=autoretry type=number min=0 value=1></div>
    </div>
   </div>
   <div class=rowf>
    <div class=field><label for=site>Site</label><input id=site type=text placeholder="ORG2026-70"></div>
    <div class=field><label for=source>Source IP</label><input id=source type=text placeholder="egress bind"></div>
   </div>
   <div class=field><label for=appliance>Appliance IP — dual-path (blank = single-target)</label><input id=appliance type=text placeholder="baseline + through-appliance, compared"></div>
   <label class=chk><input type=checkbox id=active> Active establishment (build real tunnels / pivots / exfil)</label>
   <label class=chk><input type=checkbox id=debug> Debug (verbose tools + timing)</label>
   <details class=cred id=credpanel>
    <summary>Credentials &amp; cloud NAT ports</summary>
    <div class=rowf><div class=field><label for=domain>Domain</label><input id=domain type=text></div><div class=field><label for=dcuser>DC user</label><input id=dcuser type=text></div></div>
    <div class=field><label for=dcpass>DC password</label><input id=dcpass type=password></div>
    <div class=rowf><div class=field><label for=sshuser>SSH user</label><input id=sshuser type=text></div><div class=field><label for=sshpass>SSH password</label><input id=sshpass type=password></div></div>
    <div class=credhint id=sshnote>SSH login follows the Windows/DC Administrator by default — type a different SSH value to override.</div>
    <div class=natports>
     <div class=subhead>Cloud NAT ports <span class=dim>— used by any row set to <b>cloud</b></span></div>
     <div class=rowf>
      <div class=field><label for=smb>SMB</label><input id=smb type=number value=4445></div>
      <div class=field><label for=rpc>RPC</label><input id=rpc type=number value=1135></div>
      <div class=field><label for=sshp>SSH</label><input id=sshp type=number value=22></div>
     </div>
    </div>
    <div class=loaded id=loaded></div>
   </details>
  </div>

  <div class=group>
   <div class=ghead><h2>Attack battery</h2><span class=rule></span><span class=selcount id=selcount></span></div>
   <div class=presets>
    <button data-preset=original>Original</button>
    <button data-preset=attack_sim>USS A–G</button>
    <button data-preset=added>Added</button>
    <button data-preset=all>All</button>
    <button data-preset=none>None</button>
   </div>
   <div class=battery id=battery></div>
  </div>
 </aside>

 <!-- signal theatre -->
 <section class=theatre>
  <div class=signal>
   <div class=anchor>
    <div class="big zero" id=findtally aria-live=polite>0</div>
    <div class=blabel>got through, undetected</div>
    <div class=bsub id=anchortotal>no results yet</div>
   </div>
   <div class=dist>
    <div class=dhd><span class=lab>Verdict distribution</span><span class=tot id=disttotal></span></div>
    <div class=spectrum id=spectrum><div class=empty>no results yet</div></div>
    <div class=legend id=legend></div>
   </div>
  </div>
  <div class=progress><i id=prog></i></div>
  <div class=statusbar id=runmeta>Idle — pick a target and run the battery.</div>
  <div class=cmdc id=cmdc></div>

  <div class=panel>
   <div class=tabbar role=tablist>
    <button class="tab on" id=tabRes role=tab aria-selected=true>Results</button>
    <button class=tab id=tabLog role=tab aria-selected=false>Live log</button>
    <button class=tab id=tabHist role=tab aria-selected=false>History</button>
    <span class=evidence id=evidence></span>
   </div>

   <div id=paneRes class=pane>
    <div class=vkeywrap id=vkeywrap><span class=vklabel>Verdict legend</span><div class=vkey id=vkey></div></div>
    <div class=toolbar id=resToolbar>
     <input id=fq class=fq type=text placeholder="filter… module / detail / ATT&amp;CK / CWE">
     <select id=fverdict><option value="">all verdicts</option></select>
     <select id=fcat><option value="">all categories</option></select>
     <select id=ftarget><option value="">all targets</option></select>
     <span class=rowcount id=rowcount></span>
     <span class=exp><span>export</span>
      <button data-exp=csv>CSV</button>
      <button data-exp=json>JSON</button>
      <button data-exp=md>MD</button>
     </span>
    </div>
    <div class=wrap id=resWrap><table id=restable>
     <thead><tr>
      <th data-col=n>#</th><th data-col=verdict>Verdict</th><th data-col=name>Module</th>
      <th data-col=category>Category</th><th data-col=target>Target</th><th data-col=posture>Posture</th>
      <th data-col=ports>Ports</th><th data-col=mitre>ATT&amp;CK</th><th data-col=cwe>CWE</th><th data-col=it>It</th>
      <th data-col=detail>Detail</th><th data-col=time>Time</th></tr></thead>
     <tbody id=resbody></tbody></table></div>
    <div class=empty-pane id=resempty>
     <svg class=ei viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=1.4 aria-hidden=true><circle cx=11 cy=11 r=7></circle><path d="M21 21l-4.3-4.3"></path></svg>
     <div class=et id=resemptyT>No results yet</div>
     <div class=es id=resemptyS>Pick a target, arm the battery, and run.</div>
    </div>
   </div>

   <div id=paneLog class="pane hidden"><div class=log id=log><div class=empty>No log output yet — start a run to stream live tool output here.</div></div></div>

   <div id=paneHist class="pane hidden">
    <div class=toolbar>
     <input id=hq class=fq type=text placeholder="search all runs… module / detail / ATT&amp;CK / CWE">
     <select id=hverdict><option value="">all verdicts</option></select>
     <select id=htarget><option value="">all targets</option></select>
     <select id=hsite><option value="">all sites</option></select>
     <span class=rowcount id=histcount></span>
     <span class=exp><button id=reindex title="rebuild the index from evidence/">reindex</button>
      <button data-hexp=csv>CSV</button><button data-hexp=json>JSON</button></span>
    </div>
    <div class=histroll id=histroll></div>
    <div class=wrap><table id=histtable>
     <thead><tr>
      <th data-hcol=ts>When</th><th data-hcol=verdict>Verdict</th><th data-hcol=target_ip>Target</th>
      <th data-hcol=attack>Module</th><th data-hcol=category>Category</th>
      <th data-hcol=mitre>ATT&amp;CK</th><th data-hcol=cwe>CWE</th>
      <th data-hcol=site_id>Site</th><th data-hcol=run_id>Run</th></tr></thead>
     <tbody id=histbody></tbody></table></div>
   </div>
  </div>

  <div class=runsbar>
   <div class=rh><h3>Evidence</h3><span class=runcount id=runcount></span><span class=rule></span>
    <div class="rseg evview" id=evview>
     <button type=button data-v=gallery class=on title="cards">Gallery</button>
     <button type=button data-v=list title="compact rows">List</button>
     <button type=button data-v=table title="full table">Table</button>
    </div>
   </div>
   <div class=runlist id=runs>—</div>
  </div>
 </section>
</main>
</div>

<!-- raw-output drawer -->
<div id=scrim class=scrim hidden></div>
<div id=drawer class=drawer hidden role=dialog aria-label="Raw module output">
 <div class=dhead><div class=dtitle id=dtitle></div><button id=dclose>Close</button></div>
 <div id=dmeta class=dmeta></div>
 <pre id=dbody class=dbody></pre>
</div>

<script src="static/app.js"></script>
</body></html>"""


def main():
    global TOKEN
    ap = argparse.ArgumentParser(description="Web front-end for the Control Validation Harness.")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0 = all interfaces)")
    ap.add_argument("--port", type=int, default=8080, help="bind port (default 8080)")
    ap.add_argument("--token", default=os.environ.get("HARNESS_WEB_TOKEN"),
                    help="require this token (?token= or X-Token header) on every request")
    args = ap.parse_args()
    core.enforce_latest_version()   # refuse to serve from an outdated copy (see core.py)
    TOKEN = args.token or None

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}/"
    print("=" * 66)
    print(f"  Control Validation Harness — WEB  ·  v{core.VERSION}")
    print(f"  Serving on http://{args.host}:{args.port}/   (open {url})")
    print(f"  Modules: {len(MODULES)}   ·   ROE on file: {core.roe_accepted()}"
          f"   ·   token: {'yes' if TOKEN else 'no'}")
    if args.host == "0.0.0.0":
        print("  ⚠  Bound to ALL interfaces — this control panel launches REAL")
        print("     attacks. Keep it on a trusted lab segment (or use --host")
        print("     127.0.0.1 / --token). The ROE gate still applies per run.")
    print("=" * 66)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
