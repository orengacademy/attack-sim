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
mimetypes.add_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx")
mimetypes.add_type("text/csv", ".csv")

MODULES = loader.discover()
MOD_BY_ID = {m.META["id"]: m for m in MODULES}

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
        "modules": mods, "presets": presets, "targets": targets,
        "verdict_order": _VORDER,
        "verdict_colors": {v: _VCOLOR.get(v, "#8b90a6") for v in _VORDER},
        "verdict_gloss": {v: _VGLOSS.get(v, "") for v in _VORDER},
        "categories": sorted({m["category"] for m in mods}),
    }


def _status_event(aid, name, it, b, v, target):
    me = MOD_BY_ID.get(aid)
    meta = me.META if me else {}
    return {"type": "status", "id": aid, "name": name, "it": it,
            "verdict": b, "detail": v, "target": target,
            "category": meta.get("category", ""),
            "mitre": ", ".join(meta.get("mitre", [])),
            "cwe": ", ".join(meta.get("cwe", [])),
            "direction": meta.get("direction", "a2b"),
            "ports": _ports_str(meta, target) or "—"}


# ---------------------------------------------------------------------------
# run orchestration (background thread -> per-run event queue -> SSE)
# ---------------------------------------------------------------------------
def _start_run(params):
    # ROE gate — identical policy to gui/cli: an explicit confirm or a durable opt-in.
    if not (params.get("confirm_roe") or core.roe_accepted()):
        return None, "Rules-of-engagement not confirmed (tick the ROE box)."
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
              "roots": [], "error": None, "started": time.time(), "outputs": {}}
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
            prof = core.recall_target(target) if auto else {}
            posture = core.resolve_posture(target, req_mode)
            if auto:
                t_cloud = bool(prof.get("cloud"))
                t_smb = _int(prof.get("smb_port"), 4445)
                t_rpc = _int(prof.get("rpc_port"), 1135)
                t_ssh = _int(prof.get("ssh_port"), 22)
                t_source = prof.get("source") or form_source
                t_creds = {k: prof.get(k) for k in _CRED_KEYS if prof.get(k)} or form_creds
            else:
                t_cloud, t_smb, t_rpc, t_ssh = form_cloud, form_smb, form_rpc, form_ssh
                t_source, t_creds = form_source, form_creds
            emit({"type": "target", "index": ti, "total": len(targets), "target": target,
                  "posture": posture, "cloud": bool(t_cloud)})
            if _portpatch is not None:
                if t_cloud:
                    _portpatch.CUSTOM_PORT_TARGETS[target] = {445: t_smb, 135: t_rpc, 22: t_ssh}
                else:
                    _portpatch.CUSTOM_PORT_TARGETS.pop(target, None)
            runner = core.Runner(
                target, appliance,
                on_log=lambda m: emit({"type": "log", "line": str(m)}),
                on_progress=lambda c, t: emit({"type": "progress", "done": c, "total": t}),
                on_output=lambda aid, name, it, raw, _t=target: (
                    _stash_output(st, f"{_t}|{aid}|{it}", raw),
                    emit({"type": "output", "id": aid, "name": name, "it": it, "target": _t}))[-1],
                on_status=lambda aid, name, it, b, v, _t=target: emit(_status_event(aid, name, it, b, v, _t)))
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
                if auto:
                    core.remember_target(target)   # touch last_used; don't clobber the profile
                else:
                    core.remember_target(target, source=t_source, cloud=t_cloud,
                                         smb_port=(t_smb if t_cloud else None),
                                         rpc_port=(t_rpc if t_cloud else None),
                                         ssh_port=(t_ssh if t_cloud else None),
                                         mode=posture, site_id=site_id, **t_creds)
            except Exception:
                pass
            ev = core.Evidence(label=(target if len(targets) > 1 else None))
            root = runner.run(mods, iters, ev, mode=posture, site_id=site_id)
            rel = os.path.relpath(root, HERE)
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
        if not self._authed(q):
            return self._json({"error": "unauthorized (missing/invalid token)"}, 401)
        path = u.path
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
    def _serve_evidence(self, rel):
        rel = rel.split("?")[0]
        full = os.path.normpath(os.path.join(EVID, rel))
        if not full.startswith(os.path.realpath(EVID) + os.sep) and full != os.path.realpath(EVID):
            # normpath can still escape via symlinks; compare realpaths
            if not os.path.realpath(full).startswith(os.path.realpath(EVID)):
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


def _list_runs(limit=40):
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
    for name in dirs[:limit]:
        p = os.path.join(EVID, name)
        has = {f: os.path.isfile(os.path.join(p, f))
               for f in ("report.html", "summary.json", "summary.csv", "summary.xlsx",
                         "report.txt", "attack_navigator_layer.json")}
        out.append({"name": name, "mtime": os.path.getmtime(p), "files": has})
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
<style>
:root{
 /* ---- surfaces: cool near-black, layered low->high (no pure black) ---- */
 --bg:#0a0e14; --panel:#0e141d; --panel2:#131b26; --raise:#182230; --raise2:#1f2b3b;
 --line:#202b3a; --line2:#2c3a4d; --hair:#171f2a;
 /* ---- text: cool-tinted, WCAG-checked on --bg ---- */
 --fg:#eef3f9; --fg2:#aebccd; --fg3:#7c8ca0; --faint:#6d7f94;
 /* ---- one interactive accent: cold cyan ---- */
 --acc:#5fe3e8; --acc2:#39c3cb; --acc-dim:rgba(95,227,232,.14); --acc-ink:#05282c;
 /* ---- verdict semantics = the only other hues (refined for harmony + contrast) ---- */
 --v-got:#ff5f6e; --v-det:#f7a93b; --v-blk:#38d9a0; --v-svc:#5aa2ff; --v-inc:#b79bff; --v-skip:#6f8296;
 /* ---- type ---- */
 --ui:'Space Grotesk',ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;
 --mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
 /* ---- spacing (8pt) ---- */
 --s1:4px; --s2:8px; --s3:12px; --s4:16px; --s5:20px; --s6:24px; --s7:32px;
 /* ---- radii / elevation ---- */
 --r:12px; --r-sm:8px; --r-xs:6px; --r-pill:999px;
 --sh1:0 1px 2px rgba(0,0,0,.45);
 --sh2:0 14px 34px -18px rgba(0,0,0,.75), 0 2px 8px -4px rgba(0,0,0,.5);
 --sh3:0 32px 70px -28px rgba(0,0,0,.82), 0 6px 16px -8px rgba(0,0,0,.55);
 --ring:0 0 0 3px rgba(95,227,232,.22);
 --dur:.22s; --ease:cubic-bezier(.22,1,.36,1);
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{color:var(--fg);font-family:var(--ui);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased;
 background:
   radial-gradient(1100px 520px at 84% -12%, rgba(95,227,232,.06), transparent 62%),
   radial-gradient(860px 480px at -6% 112%, rgba(183,155,255,.05), transparent 58%),
   var(--bg);
 background-attachment:fixed}
a{color:var(--acc);text-decoration:none;transition:color var(--dur)} a:hover{color:#aef3f6}
b{font-weight:600}
::selection{background:rgba(95,227,232,.26);color:#eafcfd}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px;border-radius:5px}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:20px;border:3px solid transparent;background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background:#3b4e62;background-clip:content-box}
::-webkit-scrollbar-track{background:transparent}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.num{font-family:var(--mono);font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1}

/* =========================================================== scaffold */
.shell{min-height:100%;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:var(--s5);padding:13px var(--s6);position:sticky;top:0;z-index:30;
 border-bottom:1px solid var(--line);
 background:linear-gradient(180deg,rgba(14,20,29,.94),rgba(10,14,20,.8));
 backdrop-filter:blur(16px) saturate(1.35);-webkit-backdrop-filter:blur(16px) saturate(1.35)}
.brand{display:flex;align-items:center;gap:var(--s3);min-width:0}
.mark{width:32px;height:32px;color:var(--acc);flex:none;filter:drop-shadow(0 0 9px rgba(95,227,232,.4))}
.brand .title{font-weight:600;font-size:16px;letter-spacing:-.01em;line-height:1.15}
.brand .sub{display:flex;flex-wrap:wrap;color:var(--fg3);font-size:11.5px;font-family:var(--mono);margin-top:3px}
.brand .sub>span{padding:0 9px;border-left:1px solid var(--line2);white-space:nowrap}
.brand .sub>span:first-child{padding-left:0;border-left:0}
.brand .sub>span b{color:var(--acc2)}
.cmd{margin-left:auto;display:flex;align-items:center;gap:var(--s3)}

/* ROE switch */
.switch{display:inline-flex;align-items:center;gap:var(--s2);cursor:pointer;user-select:none;white-space:nowrap;
 font-size:12.5px;color:var(--fg2);padding:6px 10px;border:1px solid var(--line);border-radius:var(--r-pill);
 background:var(--panel);transition:border-color var(--dur),color var(--dur)}
.switch:hover{border-color:var(--line2);color:var(--fg)}
.switch input{position:absolute;opacity:0;width:0;height:0}
.switch .track{width:30px;height:17px;border-radius:var(--r-pill);background:var(--raise2);position:relative;
 transition:background var(--dur) var(--ease);flex:none;box-shadow:inset 0 1px 2px rgba(0,0,0,.5)}
.switch .track::after{content:"";position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;
 background:#cdd7e2;transition:transform var(--dur) var(--ease),background var(--dur)}
.switch input:checked+.track{background:linear-gradient(180deg,var(--acc),var(--acc2))}
.switch input:checked+.track::after{transform:translateX(13px);background:var(--acc-ink)}
.switch.armed{border-color:rgba(95,227,232,.4);color:var(--fg)}
.switch input:focus-visible+.track{box-shadow:var(--ring)}

/* buttons */
.btn{font-family:var(--ui);font-weight:600;font-size:13.5px;border:1px solid var(--line2);background:var(--raise);
 color:var(--fg);border-radius:var(--r-sm);padding:9px 17px;cursor:pointer;box-shadow:var(--sh1);white-space:nowrap;
 transition:background var(--dur),border-color var(--dur),transform .08s,box-shadow var(--dur),color var(--dur)}
.btn:hover{background:var(--raise2);border-color:#3a4d61}
.btn:active{transform:translateY(1px)}
.btn:focus-visible{box-shadow:var(--ring)}
.btn.run{background:linear-gradient(180deg,var(--acc),var(--acc2));color:var(--acc-ink);border-color:transparent;
 box-shadow:0 10px 24px -12px rgba(95,227,232,.7),inset 0 1px 0 rgba(255,255,255,.4)}
.btn.run:hover{background:linear-gradient(180deg,#8bf0f4,var(--acc));filter:none}
.btn.run:disabled{background:var(--raise2);color:var(--faint);border-color:var(--line);cursor:not-allowed;box-shadow:none}
.btn.ghost{background:transparent}
.btn.stop{color:var(--v-got);border-color:#4a2a31;background:rgba(255,95,110,.06)}
.btn.stop:hover{background:rgba(255,95,110,.13);border-color:#6b3540}
.btn.stop:disabled{color:var(--faint);border-color:var(--line);background:transparent;cursor:not-allowed}
/* .btn.running: the disabled state + enabled Stop + filling progress bar signal an active run (no header animation) */

.console{flex:1;display:grid;grid-template-columns:minmax(330px,376px) 1fr;min-height:0}
.rail{border-right:1px solid var(--line);overflow:auto;background:linear-gradient(180deg,var(--panel),var(--bg) 60%)}
.theatre{overflow:auto;min-width:0}
@media(max-width:920px){.console{grid-template-columns:1fr}.rail{border-right:0;border-bottom:1px solid var(--line)}}

/* =========================================================== rail */
.group{padding:var(--s6) var(--s6) var(--s7);border-bottom:1px solid var(--hair)}
.group:last-child{border-bottom:0}
.ghead{display:flex;align-items:center;gap:var(--s2);margin:0 0 var(--s5)}
.ghead h2{font-weight:600;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--fg3);margin:0}
.ghead .rule{flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}
.field{margin-bottom:var(--s3)} .field:last-child{margin-bottom:0}
.field>label{display:block;font-size:11.5px;color:var(--fg3);margin:0 0 var(--s1);font-weight:500;letter-spacing:.01em}
input[type=text],input[type=password],input[type=number],textarea,select{width:100%;background:var(--bg);
 border:1px solid var(--line);color:var(--fg);border-radius:var(--r-sm);padding:9px 11px;font:inherit;font-size:13px;
 transition:border-color var(--dur),box-shadow var(--dur),background var(--dur)}
input::placeholder,textarea::placeholder{color:var(--faint)}
input:hover,textarea:hover,select:hover{border-color:var(--line2)}
input:focus,textarea:focus,select:focus{border-color:var(--acc2);background:var(--panel);box-shadow:var(--ring);outline:none}
textarea{font-family:var(--mono);font-size:12.5px;resize:vertical;min-height:62px;line-height:1.6}
input[type=number]{font-family:var(--mono)}
.rowf{display:flex;gap:var(--s2)} .rowf>*{flex:1;min-width:0}
.subgroup{margin:var(--s3) 0;padding:var(--s3);border:1px solid var(--hair);border-radius:var(--r-sm);
 background:linear-gradient(180deg,rgba(19,27,38,.5),rgba(10,14,20,.3))}
.subhead{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin:0 0 var(--s2);font-weight:600}
.chk{display:flex;align-items:flex-start;gap:var(--s2);font-size:12.5px;color:var(--fg2);cursor:pointer;line-height:1.45;padding:3px 0}
.chk input{accent-color:var(--acc);flex:none;margin-top:2px;width:15px;height:15px}
.chk:hover{color:var(--fg)}
details.cred{margin-top:var(--s3)}
details.cred>summary{cursor:pointer;color:var(--fg2);font-size:12.5px;list-style:none;padding:var(--s2) 0;user-select:none;
 display:flex;align-items:center;gap:var(--s2);transition:color var(--dur)}
details.cred>summary:hover{color:var(--fg)}
details.cred>summary::-webkit-details-marker{display:none}
details.cred>summary::before{content:"";width:6px;height:6px;border-right:1.6px solid var(--acc);border-bottom:1.6px solid var(--acc);
 transform:rotate(-45deg);transition:transform var(--dur) var(--ease);margin-left:2px}
details.cred[open]>summary::before{transform:rotate(45deg)}

/* posture segmented control */
.seg{display:flex;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--bg);padding:3px;gap:3px}
.seg button{flex:1;border:0;background:transparent;color:var(--fg3);font:inherit;font-size:12px;font-weight:500;padding:8px 6px;
 cursor:pointer;border-radius:var(--r-xs);transition:background var(--dur),color var(--dur)}
.seg button:hover{color:var(--fg2)}
.seg button.on{background:linear-gradient(180deg,var(--raise2),var(--raise));color:var(--fg);
 box-shadow:inset 0 0 0 1px rgba(95,227,232,.28),var(--sh1)}
/* per-target posture/transport readout (Auto mode) */
.posturemap{margin-top:var(--s2);display:flex;flex-direction:column;gap:3px;font-family:var(--mono);font-size:10.5px}
.posturemap:empty{display:none}
.posturemap .pm{display:flex;align-items:center;gap:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--fg3)}
.posturemap .pm .ip{color:var(--fg2)}
.posturemap .pm .pp{font-weight:600}
.posturemap .pm .pp.w{color:var(--acc)}
.posturemap .pm .pp.b{color:var(--fg2)}
.posturemap .pm .xp{color:var(--faint)}
.posturemap .hint{color:var(--faint);font-style:normal}

/* loaded-creds readout */
.loaded{display:flex;flex-wrap:wrap;gap:var(--s1) var(--s4);font-family:var(--mono);font-size:11px;color:var(--fg3);margin-top:var(--s3)}
.loaded span{display:inline-flex;gap:5px}
.loaded b{font-weight:500} .loaded .ok{color:var(--v-blk)} .loaded .no{color:var(--faint)}

/* presets + battery */
.presets{display:flex;flex-wrap:wrap;gap:var(--s1);margin-bottom:var(--s4)}
.presets button{font:inherit;font-size:11.5px;font-weight:500;border:1px solid var(--line);background:var(--bg);color:var(--fg3);
 border-radius:var(--r-pill);padding:5px 12px;cursor:pointer;transition:color var(--dur),border-color var(--dur),background var(--dur)}
.presets button:hover{color:var(--fg);border-color:var(--acc2);background:var(--panel)}
.selcount{margin-left:auto;font-family:var(--mono);font-size:11.5px;color:var(--acc);font-weight:500}
.battery{max-height:min(46vh,460px);overflow:auto;margin:0 calc(-1*var(--s2));padding:0 var(--s2)}
.cat{margin:var(--s4) 0 var(--s1);display:flex;align-items:center;gap:var(--s2);position:sticky;top:0;z-index:1;
 background:linear-gradient(180deg,var(--panel),rgba(14,20,29,.86));backdrop-filter:blur(6px);padding:6px 4px}
.cat .cn{font-size:10px;color:var(--fg3);font-weight:600;letter-spacing:.09em;text-transform:uppercase}
.cat .cl{flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}
.atk{display:flex;align-items:center;gap:var(--s2);padding:7px var(--s2);border-radius:var(--r-sm);cursor:pointer;
 transition:background var(--dur)}
.atk:hover{background:var(--raise)}
.atk input{accent-color:var(--acc);flex:none;width:15px;height:15px}
.atk .nm{flex:1;font-size:12.5px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--fg2)}
.atk:hover .nm{color:var(--fg)}
.atk input:checked~.nm{color:var(--fg)}
.atk .mi{font-family:var(--mono);font-size:10.5px;color:var(--faint);flex:none;text-align:right;max-width:150px;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.atk .mi .cwe{font-style:normal;color:var(--acc2);opacity:.85}
.flag{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:.04em;padding:2px 5px;border:1px solid var(--line2);
 border-radius:var(--r-xs);color:var(--fg3);flex:none;text-transform:uppercase}
.flag.new{color:var(--v-inc);border-color:rgba(183,155,255,.35);background:rgba(183,155,255,.08)}
.flag.root{color:var(--v-det);border-color:rgba(247,169,59,.35);background:rgba(247,169,59,.08)}

/* =========================================================== theatre: signal panel */
.signal{display:grid;grid-template-columns:auto 1fr;gap:var(--s7);align-items:stretch;
 padding:var(--s6) var(--s7);border-bottom:1px solid var(--line);
 background:radial-gradient(620px 240px at 10% -30%,rgba(95,227,232,.05),transparent 70%)}
@media(max-width:640px){.signal{grid-template-columns:1fr;gap:var(--s5);padding:var(--s5)}}
.anchor{display:flex;flex-direction:column;justify-content:center;min-width:150px;
 padding-right:var(--s7);border-right:1px solid var(--hair)}
@media(max-width:640px){.anchor{border-right:0;padding-right:0;border-bottom:1px solid var(--hair);padding-bottom:var(--s4)}}
.anchor .big{font-family:var(--mono);font-weight:700;font-size:64px;line-height:.82;color:var(--v-got);letter-spacing:-.04em;
 text-shadow:0 0 36px rgba(255,95,110,.42);transition:color var(--dur)}
.anchor .big.zero{color:var(--faint);text-shadow:none}
.anchor .blabel{font-size:12.5px;color:var(--fg2);margin-top:var(--s3);font-weight:500;max-width:14ch}
.anchor .bsub{font-family:var(--mono);font-size:11px;color:var(--fg3);margin-top:6px}
.dist{display:flex;flex-direction:column;justify-content:center;min-width:0}
.dist .dhd{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:var(--s2)}
.dist .dhd .lab{font-size:10px;letter-spacing:.11em;text-transform:uppercase;color:var(--fg3);font-weight:600}
.dist .dhd .tot{font-family:var(--mono);font-size:11px;color:var(--fg3)}
.spectrum{height:14px;display:flex;border-radius:var(--r-pill);overflow:hidden;background:var(--bg);
 border:1px solid var(--line);box-shadow:inset 0 1px 3px rgba(0,0,0,.6)}
.spectrum i{display:block;height:100%;transition:width .55s var(--ease);box-shadow:inset 0 0 0 1px rgba(255,255,255,.08)}
.spectrum i+i{border-left:1px solid rgba(10,14,20,.5)}
.spectrum .empty{flex:1;display:flex;align-items:center;justify-content:center;color:var(--faint);font-size:10.5px;
 font-family:var(--mono);letter-spacing:.04em}
.legend{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--s1) var(--s2);margin-top:var(--s4)}
@media(max-width:1180px){.legend{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:640px){.legend{grid-template-columns:repeat(2,minmax(0,1fr))}}
.legend .li{display:flex;align-items:center;gap:7px;font-size:11.5px;color:var(--fg2);padding:4px 2px;min-width:0}
.legend .li .sw{width:9px;height:9px;border-radius:3px;flex:none;box-shadow:0 0 7px currentColor}
.legend .li .n{font-family:var(--mono);font-weight:700;color:var(--fg);font-variant-numeric:tabular-nums;min-width:1.6ch;text-align:right}
.legend .li .nm{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--fg3)}
.legend .li.z{opacity:.55} .legend .li.z .n{color:var(--fg3);font-weight:500}

/* progress + status */
.progress{height:2px;background:var(--hair);overflow:hidden}
.progress>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--acc2),var(--acc));
 box-shadow:0 0 12px rgba(95,227,232,.65);transition:width .3s var(--ease)}
.statusbar{padding:11px var(--s7);color:var(--fg3);font-size:12px;font-family:var(--mono);border-bottom:1px solid var(--hair);
 display:flex;align-items:center;gap:var(--s2)}
.statusbar::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--faint);flex:none;transition:background var(--dur)}
.statusbar.run{color:var(--fg2)} .statusbar.run::before{background:var(--acc);box-shadow:0 0 8px var(--acc)}
.statusbar.ok::before{background:var(--v-blk);box-shadow:0 0 8px var(--v-blk)}
.statusbar.err{color:var(--v-got)} .statusbar.err::before{background:var(--v-got);box-shadow:0 0 8px var(--v-got)}

/* =========================================================== panel (tabs) */
.panel{padding:0 0 var(--s4)}
.tabbar{display:flex;align-items:center;gap:0;padding:var(--s4) var(--s7) 0;border-bottom:1px solid var(--line)}
.tab{font:inherit;font-size:13px;font-weight:500;border:0;background:transparent;color:var(--fg3);padding:9px 2px;margin-right:var(--s6);
 cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color var(--dur),border-color var(--dur)}
.tab:hover{color:var(--fg2)} .tab.on{color:var(--fg);border-bottom-color:var(--acc)}
.evidence{margin-left:auto;font-family:var(--mono);font-size:11.5px;color:var(--fg3);padding-bottom:9px}
.evidence b{color:var(--fg3);font-weight:500}
.evidence a{margin-left:9px}

.pane{padding-top:var(--s4);animation:fade var(--dur) var(--ease)}
@keyframes fade{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}

/* verdict key (collapsed glossary) */
.vkeywrap{margin:0 var(--s7) var(--s3)}
.vkeywrap>summary{cursor:pointer;color:var(--fg3);font-size:11.5px;padding:var(--s2) 0;list-style:none;user-select:none;
 display:inline-flex;align-items:center;gap:var(--s2);transition:color var(--dur)}
.vkeywrap>summary:hover{color:var(--fg2)}
.vkeywrap>summary::-webkit-details-marker{display:none}
.vkeywrap>summary::before{content:"";width:5px;height:5px;border-right:1.5px solid var(--acc);border-bottom:1.5px solid var(--acc);
 transform:rotate(-45deg);transition:transform var(--dur) var(--ease)}
.vkeywrap[open]>summary::before{transform:rotate(45deg)}
.vkey{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s2);padding:var(--s3) 0 var(--s1)}
@media(max-width:720px){.vkey{grid-template-columns:1fr}}
.vkey .vk{display:flex;align-items:center;gap:var(--s2);padding:8px 11px;border:1px solid var(--line);
 border-radius:var(--r-sm);background:var(--panel);cursor:pointer;transition:border-color var(--dur),background var(--dur)}
.vkey .vk:hover{border-color:var(--line2);background:var(--raise)}
.vkey .vk.on{border-color:var(--acc);background:var(--raise);box-shadow:inset 0 0 0 1px rgba(95,227,232,.25)}
.vkey .vk .sw{width:9px;height:9px;border-radius:3px;flex:none;box-shadow:0 0 7px currentColor}
.vkey .vk b{color:var(--fg);font-family:var(--mono);font-weight:600;font-size:10.5px;flex:none;letter-spacing:.02em}
.vkey .vk span{color:var(--fg3);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* toolbar (results + history) */
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:var(--s2);padding:var(--s2) var(--s7) var(--s3)}
.toolbar input,.toolbar select{width:auto;min-width:118px;padding:7px 9px;font-size:12px}
.toolbar input.fq{flex:1;min-width:190px}
.toolbar .rowcount{color:var(--fg3);font-size:11px;font-family:var(--mono);white-space:nowrap}
.toolbar .exp{margin-left:auto;color:var(--fg3);font-size:11px;display:flex;align-items:center;gap:var(--s1)}
.toolbar .exp>span{margin-right:2px}
.toolbar .exp button{padding:6px 11px;font-size:11px;font-weight:500;font-family:var(--mono);background:var(--panel);
 border:1px solid var(--line);color:var(--fg2);border-radius:var(--r-xs);cursor:pointer;
 transition:border-color var(--dur),color var(--dur),background var(--dur)}
.toolbar .exp button:hover{border-color:var(--acc2);color:var(--fg);background:var(--raise)}

/* table shell */
.wrap{max-height:52vh;overflow:auto;margin:0 var(--s7);border:1px solid var(--line);border-radius:var(--r);
 background:var(--panel)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead th{position:sticky;top:0;z-index:2;background:var(--panel2);text-align:left;font-weight:600;color:var(--fg3);
 font-size:10px;letter-spacing:.06em;text-transform:uppercase;padding:10px 11px;border-bottom:1px solid var(--line);
 cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{color:var(--fg)} thead th .ar{color:var(--acc);font-size:9px;margin-left:4px}
tbody td{padding:9px 11px;border-bottom:1px solid var(--hair);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr{cursor:pointer;transition:background .12s}
tbody tr:hover{background:var(--raise)}
tbody tr.ins{animation:rowin .4s var(--ease)}
@keyframes rowin{from{opacity:0;background:var(--acc-dim)}to{opacity:1}}
td.cell-n{color:var(--faint)}
/* verdict chip */
.vchip{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-weight:600;font-size:10.5px;
 letter-spacing:.02em;white-space:nowrap;padding:2px 8px 2px 6px;border-radius:var(--r-pill);
 border:1px solid currentColor;line-height:1.5}
.vchip .d{width:7px;height:7px;border-radius:50%;background:currentColor;flex:none;box-shadow:0 0 6px currentColor}
.vchip .t{color:var(--fg)}
.detail{color:var(--fg2);max-width:460px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.5;max-height:3em}
td.dim{color:var(--fg3)}

/* empty state */
.empty-pane{margin:var(--s2) var(--s7) var(--s4);border:1px dashed var(--line2);border-radius:var(--r);
 padding:var(--s7) var(--s6);text-align:center;background:linear-gradient(180deg,var(--panel),rgba(10,14,20,.3))}
.empty-pane .ei{width:38px;height:38px;color:var(--faint);margin:0 auto var(--s3)}
.empty-pane .et{color:var(--fg2);font-size:13.5px;font-weight:500}
.empty-pane .es{color:var(--fg3);font-size:12px;margin-top:6px}
.empty-pane.run .ei{color:var(--acc)}

/* live log */
.log{height:50vh;overflow:auto;margin:0 var(--s7);padding:var(--s4) var(--s5);background:var(--bg);border:1px solid var(--line);
 border-radius:var(--r);font-family:var(--mono);font-size:12px;white-space:pre-wrap;line-height:1.65;
 box-shadow:inset 0 1px 3px rgba(0,0,0,.45)}
.log div{padding-left:1px}
.log .c-got{color:var(--v-got)} .log .c-blk{color:var(--v-blk)} .log .c-svc{color:var(--v-svc)}
.log .c-det{color:var(--v-det)} .log .c-hdr{color:var(--acc)} .log .c-mut{color:var(--faint)}
.log .empty{color:var(--faint)}

/* history rollup */
.histroll{display:flex;flex-wrap:wrap;gap:var(--s2);padding:0 var(--s7) var(--s3)}
.histroll .hr{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border:1px solid var(--line);
 border-radius:var(--r-pill);background:var(--panel);color:var(--fg3);font-size:11.5px}
.histroll .hr i{width:8px;height:8px;border-radius:50%;flex:none;box-shadow:0 0 6px currentColor}
.histroll .hr b{color:var(--fg);font-family:var(--mono);font-weight:600;font-variant-numeric:tabular-nums}
.histroll .hr.runs{border-color:var(--line2);color:var(--fg2)}
.histroll .hr.runs i{background:var(--acc)}

/* raw-output drawer */
.scrim{position:fixed;inset:0;background:rgba(5,8,12,.6);backdrop-filter:blur(2px);z-index:45;animation:fade var(--dur) var(--ease)}
.scrim[hidden]{display:none}
.drawer{position:fixed;top:0;right:0;width:min(820px,96vw);height:100dvh;z-index:46;
 background:linear-gradient(180deg,var(--panel2),var(--panel));border-left:1px solid var(--line2);box-shadow:var(--sh3);
 display:flex;flex-direction:column;animation:slidein .26s var(--ease)}
@keyframes slidein{from{transform:translateX(26px);opacity:.4}to{transform:none;opacity:1}}
.drawer[hidden]{display:none}
.drawer .dhead{display:flex;align-items:center;justify-content:space-between;gap:var(--s3);padding:var(--s4) var(--s5);
 border-bottom:1px solid var(--line)}
.drawer .dhead .dtitle{display:flex;align-items:center;gap:var(--s3);min-width:0;font-weight:600;font-size:14px}
.drawer .dhead .dtitle .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.drawer .dhead button{padding:6px 13px;background:var(--panel);border:1px solid var(--line);color:var(--fg2);
 border-radius:var(--r-xs);cursor:pointer;font:inherit;font-size:12px;transition:border-color var(--dur),color var(--dur)}
.drawer .dhead button:hover{border-color:var(--acc2);color:var(--fg)}
.drawer .dmeta{padding:10px var(--s5);color:var(--fg3);font-size:11.5px;font-family:var(--mono);border-bottom:1px solid var(--hair);
 display:flex;flex-wrap:wrap;gap:var(--s1) var(--s3)}
.drawer .dmeta span{white-space:nowrap}
.drawer .dbody{flex:1;overflow:auto;margin:0;padding:var(--s5);font-family:var(--mono);font-size:12px;white-space:pre-wrap;
 line-height:1.65;color:var(--fg2);background:var(--bg)}

/* recent evidence */
.runsbar{padding:var(--s6) var(--s7) var(--s7);border-top:1px solid var(--hair)}
.runsbar .rh{display:flex;align-items:center;gap:var(--s2);margin:0 0 var(--s4)}
.runsbar h3{font-size:11px;font-weight:600;color:var(--fg3);margin:0;letter-spacing:.11em;text-transform:uppercase}
.runsbar .rh .rule{flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}
.runlist{display:grid;grid-template-columns:repeat(auto-fill,minmax(256px,1fr));gap:var(--s2)}
.runrow{display:flex;flex-direction:column;align-items:stretch;gap:8px;padding:11px 13px;border:1px solid var(--hair);
 border-radius:var(--r-sm);background:var(--panel);transition:border-color var(--dur),background var(--dur)}
.runrow:hover{border-color:var(--line2);background:var(--raise)}
.runrow .rn{font-family:var(--mono);font-size:12px;color:var(--fg);font-weight:500;letter-spacing:-.01em;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.runrow .rlinks{display:flex;align-items:center;flex-wrap:wrap;gap:4px}
.runrow .rlinks a{font-family:var(--mono);font-size:10.5px;color:var(--fg3);padding:3px 8px;border-radius:var(--r-xs);
 border:1px solid var(--hair);transition:color var(--dur),border-color var(--dur),background var(--dur)}
.runrow .rlinks a:hover{color:var(--fg);border-color:var(--line2);background:var(--panel2)}
.runrow .rlinks a.primary{color:var(--acc);border-color:rgba(95,227,232,.3);background:var(--acc-dim)}
.runrow .rlinks a.primary:hover{color:var(--acc-ink);background:var(--acc);border-color:var(--acc)}
.runrow .nolink{color:var(--faint);font-size:11px;font-family:var(--mono)}

.hidden{display:none!important}

@media(prefers-reduced-motion:reduce){
 *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}
 .spectrum i{transition:none}
}
@media(max-width:560px){
 .topbar{flex-wrap:wrap;gap:var(--s3);padding:11px var(--s4)}
 .cmd{width:100%;justify-content:flex-end}
 .group{padding:var(--s5) var(--s4) var(--s6)}
 .signal,.statusbar,.tabbar,.toolbar,.wrap,.log,.vkeywrap,.histroll,.runsbar{padding-left:var(--s4);padding-right:var(--s4)}
 .wrap,.log{margin-left:var(--s4);margin-right:var(--s4)}
 .anchor .big{font-size:52px}
}
</style></head>
<body><div class=shell>

<header class=topbar>
 <div class=brand>
  <svg class=mark viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
   <circle cx="12" cy="12" r="7.5"></circle>
   <path d="M12 1.5V6M12 18v4.5M1.5 12H6M18 12h4.5"></path>
   <circle cx="12" cy="12" r="1.8" fill="currentColor" stroke="none"></circle>
  </svg>
  <div>
   <div class=title>Control Validation Harness</div>
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
    <label for=targets>Targets — one host per line</label>
    <textarea id=targets placeholder="159.223.35.108&#10;167.71.222.169"></textarea>
   </div>
   <div class=field>
    <label>Posture</label>
    <div class=seg id=modeseg>
     <button data-v=auto class=on title="each target runs in its own designated posture">Auto · per-target</button>
     <button data-v=blackbox title="through the SD-WAN as-is">Black-box</button>
     <button data-v=whitebox title="allow-all baseline">White-box</button>
    </div>
    <div class=posturemap id=postureMap></div>
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
    <label class=chk style="margin:var(--s2) 0"><input type=checkbox id=cloud> Cloud target (NAT'd SMB/RPC/SSH)</label>
    <div class=rowf>
     <div class=field><label for=smb>SMB</label><input id=smb type=number value=4445></div>
     <div class=field><label for=rpc>RPC</label><input id=rpc type=number value=1135></div>
     <div class=field><label for=sshp>SSH</label><input id=sshp type=number value=22></div>
    </div>
    <div class=rowf><div class=field><label for=domain>Domain</label><input id=domain type=text></div><div class=field><label for=dcuser>DC user</label><input id=dcuser type=text></div></div>
    <div class=field><label for=dcpass>DC password</label><input id=dcpass type=password></div>
    <div class=rowf><div class=field><label for=sshuser>SSH user</label><input id=sshuser type=text></div><div class=field><label for=sshpass>SSH password</label><input id=sshpass type=password></div></div>
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

  <div class=panel>
   <div class=tabbar role=tablist>
    <button class="tab on" id=tabRes role=tab aria-selected=true>Results</button>
    <button class=tab id=tabLog role=tab aria-selected=false>Live log</button>
    <button class=tab id=tabHist role=tab aria-selected=false>History</button>
    <span class=evidence id=evidence></span>
   </div>

   <div id=paneRes class=pane>
    <details class=vkeywrap><summary>Verdict key — what each outcome means</summary><div class=vkey id=vkey></div></details>
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
      <th data-col=category>Category</th><th data-col=target>Target</th><th data-col=ports>Ports</th>
      <th data-col=mitre>ATT&amp;CK</th><th data-col=cwe>CWE</th><th data-col=it>It</th>
      <th data-col=detail>Detail</th></tr></thead>
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
   <div class=rh><h3>Recent evidence</h3><span class=rule></span></div>
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

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let BOOT=null, MODE="auto", ES=null, COUNTS={}, RESN=0;
let ROWS=[], RUNID=null, SORT={col:"n",dir:1}, RUNNING=false;
// 6-bucket visual grouping (spectrum / legend / row colors)
const KIND={SUCCESS:"got",DETECTED:"det",BLOCKED:"blk","NO-SERVICE":"svc",
 "AUTH-FAILED":"det","NO-RESULT":"det",INCONCLUSIVE:"inc",SKIPPED:"skip","PREREQ-MISSING":"skip"};
// one harmonised palette, shared by every colored element on the page
const HEX={got:"#ff5f6e",det:"#f7a93b",blk:"#38d9a0",svc:"#5aa2ff",inc:"#b79bff",skip:"#6f8296"};
const LABEL={got:"got through",det:"detected / review",blk:"held",svc:"no service",inc:"inconclusive",skip:"skipped"};
const ORDER=["got","det","blk","svc","inc","skip"];
// exact verdict -> hex (verdict key + history rollup), kept consistent with the buckets above
const VHEX={SUCCESS:HEX.got,DETECTED:HEX.det,"AUTH-FAILED":HEX.det,"NO-RESULT":HEX.det,
 BLOCKED:HEX.blk,"NO-SERVICE":HEX.svc,INCONCLUSIVE:HEX.inc,SKIPPED:HEX.skip,"PREREQ-MISSING":HEX.skip};
const esc=s=>(s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const kindOf=v=>KIND[v]||"det";
const vcolor=v=>VHEX[v]||HEX[kindOf(v)];

async function boot(){
 BOOT=await (await fetch("api/bootstrap")).json();
 const s=$("#subline"); s.innerHTML="";
 const bits=["<b>v"+esc(BOOT.version)+"</b>"+(BOOT.engine?(" ("+esc(BOOT.engine)+")"):""), esc(BOOT.policy||"no policy"), BOOT.modules.length+" modules"];
 bits.forEach(t=>{const x=document.createElement("span");x.innerHTML=t;s.appendChild(x);});
 $("#workers").value=BOOT.workers; $("#roe").checked=BOOT.roe; syncRoe();
 const cl=BOOT.creds_loaded, L=$("#loaded"); L.innerHTML="";
 Object.entries(cl).forEach(([k,v])=>{const e=document.createElement("span");
  e.innerHTML=esc(k.replace("_"," "))+" <b class="+(v?"ok":"no")+">"+(v?"set":"—")+"</b>";L.appendChild(e);});
 const C=BOOT.creds||{};
 $("#domain").value=C.domain||""; $("#dcuser").value=C.dc_user||""; $("#dcpass").value=C.dc_pass||"";
 $("#sshuser").value=C.ssh_user||""; $("#sshpass").value=C.ssh_pass||"";
 if(Object.values(cl).some(Boolean) || Object.keys(BOOT.target_config||{}).length)
   { const d=$("#credpanel"); if(d) d.open=true; }
 if(BOOT.targets&&BOOT.targets.length){ $("#targets").value=BOOT.targets.join("\n");
   prefillTarget(BOOT.targets[0]); }
 $("#targets").addEventListener("input",()=>{
   const first=$("#targets").value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean)[0];
   if(first) prefillTarget(first); renderPostureMap();});
 buildBattery(); buildVerdictKey(); applyPreset("original"); refresh(); renderRows(); renderPostureMap(); loadRuns();
}

// Prefill the whole form for ONE target from its saved config.
function prefillTarget(ip){
 const tc=(BOOT.target_config||{})[ip]; if(!tc) return;
 $("#cloud").checked=!!tc.cloud;
 if(tc.smb_port) $("#smb").value=tc.smb_port;
 if(tc.rpc_port) $("#rpc").value=tc.rpc_port;
 if(tc.ssh_port) $("#sshp").value=tc.ssh_port;
 if(tc.source) $("#source").value=tc.source;
 if(tc.site_id) $("#site").value=tc.site_id;
 if(tc.domain) $("#domain").value=tc.domain;
 if(tc.dc_user) $("#dcuser").value=tc.dc_user;
 if(tc.dc_pass) $("#dcpass").value=tc.dc_pass;
 if(tc.ssh_user) $("#sshuser").value=tc.ssh_user;
 if(tc.ssh_pass) $("#sshpass").value=tc.ssh_pass;
 // posture is NOT forced onto the global toggle any more — 'Auto · per-target'
 // resolves each target's designated posture at run time (see renderPostureMap).
}
// Show each entered target's resolved posture + transport. In Auto, read it from
// that target's saved profile; in explicit, the chosen posture applies to all.
function renderPostureMap(){
 const host=$("#postureMap"); if(!host) return;
 const ips=$("#targets").value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
 const tc=BOOT&&BOOT.target_config||{};
 if(!ips.length){ host.innerHTML=""; return; }
 if(MODE!=="auto"){
  host.innerHTML=`<span class=pm><span class=hint>explicit <b>${esc(MODE)}</b> applied to all ${ips.length} target(s) — form config used</span></span>`;
  return;
 }
 host.innerHTML=ips.slice(0,8).map(ip=>{
  const p=tc[ip]||{}; const post=(String(p.mode||"").toLowerCase().startsWith("w"))?"whitebox":"blackbox";
  const cls=post==="whitebox"?"w":"b";
  const known=!!tc[ip];
  const xport=p.cloud?("cloud "+(p.smb_port||4445)+"/"+(p.rpc_port||1135)):"on-prem direct";
  const tail=known?`<span class=xp>· ${esc(xport)}</span>`:`<span class=xp>· not designated → blackbox · on-prem</span>`;
  return `<span class=pm><span class=ip>${esc(ip)}</span> <span class="pp ${cls}">${post}</span> ${tail}</span>`;
 }).join("")+(ips.length>8?`<span class=pm><span class=hint>+${ips.length-8} more…</span></span>`:"");
}
function syncRoe(){ $("#roeswitch").classList.toggle("armed",$("#roe").checked); }

// Verdict key: every verdict with color + plain-language meaning; each chip also toggles the table filter.
function buildVerdictKey(){
 const host=$("#vkey"); if(!host)return; host.innerHTML="";
 (BOOT.verdict_order||[]).forEach(v=>{
  const c=vcolor(v), g=(BOOT.verdict_gloss||{})[v]||"";
  const el=document.createElement("div"); el.className="vk"; el.dataset.v=v; el.title=v+" — "+g;
  el.innerHTML=`<i class=sw style="color:${c}"></i><b>${esc(v)}</b><span>${esc(g)}</span>`;
  el.addEventListener("click",()=>{
    const f=$("#fverdict");
    if(f.value===v){f.value="";}
    else{ if(![...f.options].some(o=>o.value===v)){const o=document.createElement("option");o.value=o.textContent=v;f.appendChild(o);} f.value=v; }
    renderRows();});
  host.appendChild(el);});
}
function markVerdictKey(){const cur=$("#fverdict").value;
 $$("#vkey .vk").forEach(el=>el.classList.toggle("on",el.dataset.v===cur&&cur!==""));}
function buildBattery(){
 const host=$("#battery"); host.innerHTML="";
 const byCat={}; BOOT.modules.forEach(m=>{(byCat[m.category]=byCat[m.category]||[]).push(m);});
 Object.keys(byCat).sort().forEach(cat=>{
  host.insertAdjacentHTML("beforeend",`<div class=cat><span class=cn>${esc(cat)}</span><span class=cl></span></div>`);
  byCat[cat].forEach(m=>{
   const flags=(m.added?'<span class="flag new">new</span>':'')+(m.needs_root?'<span class="flag root">root</span>':'');
   const mi=(m.mitre||[]).join(", "), cw=(m.cwe||[]).join(", ");
   const det=[m.category, m.tactic, (m.family?("family "+m.family):""), m.direction,
     (mi?("ATT&CK "+mi):""), (cw?("CWE "+cw):""), (m.cve?("CVE "+m.cve):""),
     (m.ports?("ports "+m.ports):""), (m.control?("control: "+m.control):""),
     (m.fix?("owner: "+m.fix):""), (m.test_type?("["+m.test_type+"]"):"")
     ].filter(Boolean).join("  •  ");
   host.insertAdjacentHTML("beforeend",
    `<label class=atk title="${esc(det)}"><input type=checkbox data-id="${m.id}">`
    +`<span class=nm>${esc(m.name)}</span>${flags}`
    +`<span class=mi>${esc(mi||'—')}${cw?(' <i class=cwe>'+esc(cw)+'</i>'):''}</span></label>`);
  });
 });
 host.addEventListener("change",updSel);
}
function applyPreset(p){const ids=p==="none"?[]:(BOOT.presets[p]||[]);
 $$("#battery input").forEach(cb=>cb.checked=ids.includes(cb.dataset.id));updSel();}
function updSel(){$("#selcount").textContent=$$("#battery input:checked").length+" armed";}
const selectedIds=()=>$$("#battery input:checked").map(cb=>cb.dataset.id);

function refresh(){
 const groups={}; let total=0;
 Object.entries(COUNTS).forEach(([v,n])=>{const k=kindOf(v);groups[k]=(groups[k]||0)+n;total+=n;});
 const spec=$("#spectrum");
 if(!total){spec.innerHTML='<div class=empty>no results yet</div>';}
 else{spec.innerHTML=ORDER.filter(k=>groups[k]).map(k=>
   `<i style="width:${100*groups[k]/total}%;background:${HEX[k]}" title="${LABEL[k]}: ${groups[k]}"></i>`).join("");}
 $("#legend").innerHTML=ORDER.map(k=>{const n=groups[k]||0;
  return `<span class="li${n?'':' z'}"><i class=sw style="color:${HEX[k]}"></i><b class=n>${n}</b><span class=nm>${LABEL[k]}</span></span>`;}).join("");
 const got=groups.got||0;
 const ft=$("#findtally"); ft.textContent=got; ft.classList.toggle("zero",got===0);
 $("#disttotal").textContent=total?(total+" check"+(total===1?"":"s")):"";
 $("#anchortotal").textContent=total?("of "+total+" check"+(total===1?"":"s")):(RUNNING?"running…":"no results yet");
}

function addRow(e){
 const row={n:++RESN, verdict:e.verdict||"", id:e.id||"", name:e.name||"", category:e.category||"",
  target:e.target||"", ports:e.ports||"", mitre:e.mitre||"", cwe:e.cwe||"", it:e.it||1, detail:e.detail||""};
 ROWS.push(row);
 COUNTS[e.verdict]=(COUNTS[e.verdict]||0)+1;
 syncFilterOptions(); renderRows(row.n); refresh();
}
function syncFilterOptions(){
 const add=(sel,vals)=>{const cur=sel.value; const have=new Set([...sel.options].map(o=>o.value));
  [...vals].sort().forEach(v=>{if(v&&!have.has(v)){const o=document.createElement("option");o.value=o.textContent=v;sel.appendChild(o);}});
  sel.value=cur;};
 add($("#fverdict"), new Set(ROWS.map(r=>r.verdict)));
 add($("#fcat"),     new Set(ROWS.map(r=>r.category)));
 add($("#ftarget"),  new Set(ROWS.map(r=>r.target)));
}
function filteredRows(){
 const q=$("#fq").value.trim().toLowerCase(), fv=$("#fverdict").value, fc=$("#fcat").value, ft=$("#ftarget").value;
 let rows=ROWS.filter(r=>(!fv||r.verdict===fv)&&(!fc||r.category===fc)&&(!ft||r.target===ft)
   &&(!q||[r.name,r.detail,r.mitre,r.cwe,r.id,r.category].join(" ").toLowerCase().includes(q)));
 const c=SORT.col, d=SORT.dir, num=(c==="n"||c==="it");
 rows.sort((a,b)=>{let x=a[c],y=b[c]; if(num){x=+x;y=+y;} else {x=(""+x).toLowerCase();y=(""+y).toLowerCase();}
   return x<y?-d:x>y?d:a.n-b.n;});
 return rows;
}
// toggle results chrome (table vs empty-state); insN = row number just inserted (for the entrance anim)
function updateResultsChrome(){
 const empty=ROWS.length===0;
 $("#resToolbar").classList.toggle("hidden",empty);
 $("#resWrap").classList.toggle("hidden",empty);
 $("#paneRes .vkeywrap").classList.toggle("hidden",empty);
 $("#resempty").classList.toggle("hidden",!empty);
 if(empty){
  const run=RUNNING;
  $("#resempty").classList.toggle("run",run);
  $("#resemptyT").textContent=run?"Running — awaiting first result":"No results yet";
  $("#resemptyS").textContent=run?"Live verdicts stream in as each module finishes.":"Pick a target, arm the battery, and run.";
 }
}
function renderRows(insN){
 updateResultsChrome();
 const rows=filteredRows(), tb=$("#resbody"); tb.innerHTML="";
 rows.forEach(r=>{const c=HEX[kindOf(r.verdict)];
  const tr=document.createElement("tr");
  tr.dataset.id=r.id; tr.dataset.it=r.it; tr.dataset.target=r.target;
  if(insN&&r.n===insN) tr.className="ins";
  tr.innerHTML=`<td class="mono cell-n">${r.n}</td>`
   +`<td><span class=vchip style="color:${c}"><span class=d></span><span class=t>${esc(r.verdict)}</span></span></td>`
   +`<td>${esc(r.name)}</td><td class=dim>${esc(r.category)}</td>`
   +`<td class=mono>${esc(r.target)}</td><td class=mono>${esc(r.ports)}</td>`
   +`<td class=mono>${esc(r.mitre)}</td><td class=mono>${esc(r.cwe)}</td><td class="mono cell-n">${r.it}</td>`
   +`<td class=detail title="${esc(r.detail)}">${esc(r.detail)}</td>`;
  tr.addEventListener("click",()=>openRow(r));
  tb.appendChild(tr);});
 markVerdictKey();
 $("#rowcount").textContent=ROWS.length?(rows.length+(rows.length===ROWS.length?"":" / "+ROWS.length)+" rows"):"";
 $$("#restable thead th").forEach(th=>{const a=th.querySelector(".ar"); if(a)a.remove();
  if(th.dataset.col===SORT.col){const s=document.createElement("span");s.className="ar";s.textContent=SORT.dir>0?"▲":"▼";th.appendChild(s);}});
}
// click a results row -> fetch that module's raw output and show it in the drawer
async function openRow(r){
 const c=HEX[kindOf(r.verdict)];
 $("#dtitle").innerHTML=`<span class=vchip style="color:${c}"><span class=d></span><span class=t>${esc(r.verdict)}</span></span><span class=nm>${esc(r.name)}</span>`;
 $("#dmeta").innerHTML=[r.target,r.category,r.ports,r.mitre&&("ATT&CK "+r.mitre),r.cwe&&("CWE "+r.cwe),"iter "+r.it]
   .filter(Boolean).map(x=>"<span>"+esc(x)+"</span>").join("");
 $("#dbody").textContent="loading raw output…";
 openDrawer();
 if(!RUNID){$("#dbody").textContent=r.detail||"(no run context)";return;}
 try{
  const u="api/run/"+RUNID+"/output?target="+encodeURIComponent(r.target)+"&id="+encodeURIComponent(r.id)+"&it="+encodeURIComponent(r.it);
  const j=await (await fetch(u)).json();
  $("#dbody").textContent=j.output!=null?j.output:("(no captured output — "+(j.error||"")+")\n\nverdict detail:\n"+r.detail);
 }catch(err){$("#dbody").textContent="(could not load output: "+err+")\n\nverdict detail:\n"+r.detail;}
}
function openDrawer(){$("#scrim").hidden=false;$("#drawer").hidden=false;}
function closeDrawer(){$("#scrim").hidden=true;$("#drawer").hidden=true;}
// export the CURRENTLY FILTERED rows
function exportRows(fmt){
 const rows=filteredRows(), cols=["n","verdict","name","id","category","target","ports","mitre","cwe","it","detail"];
 let data,mime,ext;
 if(fmt==="json"){data=JSON.stringify(rows,null,1);mime="application/json";ext="json";}
 else if(fmt==="md"){data="| "+cols.join(" | ")+" |\n|"+cols.map(()=>"---").join("|")+"|\n"
   +rows.map(r=>"| "+cols.map(c=>(""+r[c]).replace(/\|/g,"\\|").replace(/\n/g," ")).join(" | ")+" |").join("\n");mime="text/markdown";ext="md";}
 else{const q=s=>'"'+(""+s).replace(/"/g,'""')+'"';
   data=cols.join(",")+"\n"+rows.map(r=>cols.map(c=>q(r[c])).join(",")).join("\n");mime="text/csv";ext="csv";}
 const a=document.createElement("a");
 a.href=URL.createObjectURL(new Blob([data],{type:mime}));
 a.download="results-"+(new Date().toISOString().slice(0,19).replace(/[:T]/g,"-"))+"."+ext;
 a.click();URL.revokeObjectURL(a.href);
}
function logLine(t){
 const l=t.toLowerCase(); let c="";
 if(l.includes("success")||l.includes("[finding]")||l.includes("got through")) c="c-got";
 else if(l.includes("no-service")) c="c-svc";
 else if(l.includes("blocked")||l.includes("control working")||l.includes("held")) c="c-blk";
 else if(l.includes("[warn]")||l.includes("[error]")||l.includes("no-result")||l.includes("auth-failed")||l.includes("detected")) c="c-det";
 else if(t.startsWith("====")||t.startsWith("[")||t.startsWith("Platform")||t.startsWith("Recon")||t.startsWith("Preflight")||t.startsWith("Port policy")) c="c-hdr";
 const d=document.createElement("div"); if(c)d.className=c; d.textContent=t;
 const L=$("#log"); const em=L.querySelector(".empty"); if(em)em.remove();
 L.appendChild(d); L.scrollTop=L.scrollHeight;
}

function startRun(){
 const targets=$("#targets").value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
 const body={targets,module_ids:selectedIds(),mode:MODE,
  iterations:+$("#iters").value,workers:+$("#workers").value,wait_unblock:+$("#wait").value,
  ban_expiry:+$("#banexp").value,auto_retry:+$("#autoretry").value,
  site_id:$("#site").value,source:$("#source").value,appliance:$("#appliance").value,
  active:$("#active").checked,debug:$("#debug").checked,confirm_roe:$("#roe").checked,
  cloud:$("#cloud").checked,smb_port:+$("#smb").value,rpc_port:+$("#rpc").value,ssh_port:+$("#sshp").value,
  creds:{domain:$("#domain").value,dc_user:$("#dcuser").value,dc_pass:$("#dcpass").value,
         ssh_user:$("#sshuser").value,ssh_pass:$("#sshpass").value}};
 fetch("api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
  .then(r=>r.json()).then(j=>{
   if(j.error){setStatus(j.error,"err");return;}
   RUNNING=true;
   COUNTS={};RESN=0;ROWS=[];RUNID=j.run_id;$("#resbody").innerHTML="";$("#rowcount").textContent="";
   $("#log").innerHTML="";$("#evidence").textContent="";$("#prog").style.width="0";
   refresh();renderRows();
   $("#runbtn").disabled=true;$("#runbtn").classList.add("running");
   $("#stopbtn").disabled=false;$("#stopbtn").dataset.id=j.run_id;
   stream(j.run_id);
  });
}
function setStatus(txt,cls){const el=$("#runmeta");el.textContent=txt;el.className="statusbar"+(cls?(" "+cls):"");}
function stream(id){
 if(ES)ES.close(); ES=new EventSource("api/run/"+id+"/stream");
 ES.onmessage=ev=>{const e=JSON.parse(ev.data);
  if(e.type==="log")logLine(e.line);
  else if(e.type==="status")addRow(e);
  else if(e.type==="progress")$("#prog").style.width=(e.total?100*e.done/e.total:0)+"%";
  else if(e.type==="started"){const pm=(e.mode==="auto")?"auto · per-target":e.mode;
    setStatus(`running ${e.count} modules · ${pm} · ${e.iterations} iteration(s) · ${e.workers} workers`+(e.site_id?` · site ${e.site_id}`:"")+(e.active?" · active":""),"run");}
  else if(e.type==="target")logLine(`\n==== target ${e.index}/${e.total}: ${e.target}`+(e.posture?` · ${e.posture}`:"")+(e.cloud?" · cloud":"")+` ====`);
  else if(e.type==="target_done")showEvidence(e.root);
  else if(e.type==="done")finish();
  else if(e.type==="error"){logLine("[error] "+e.error);finish(e.error);}
 };
 ES.onerror=()=>{};
}
function showEvidence(root){
 const b="evidence/"+root.replace(/^evidence\//,"")+"/";
 $("#evidence").innerHTML="<b>evidence</b> "
  +`<a target=_blank href="${b}report.html">report</a>`
  +`<a target=_blank href="${b}summary.json">json</a>`
  +`<a href="${b}summary.csv">csv</a>`
  +`<a href="${b}summary.xlsx">xlsx</a>`
  +`<a target=_blank href="${b}report.txt">txt</a>`;
}
function finish(err){
 RUNNING=false;
 $("#runbtn").disabled=false;$("#runbtn").classList.remove("running");$("#stopbtn").disabled=true;
 const got=Object.entries(COUNTS).filter(([v])=>kindOf(v)==="got").reduce((a,[,n])=>a+n,0);
 if(err){setStatus("run ended with an error — see the live log","err");}
 else{setStatus(got?`run complete — ${got} got through`:"run complete — no findings got through","ok");}
 renderRows();
 if(ES)ES.close(); loadRuns();
}
async function loadRuns(){
 const j=await (await fetch("api/runs")).json();
 const FMT=[["report.html","report"],["summary.json","json"],["summary.csv","csv"],["summary.xlsx","xlsx"],["report.txt","txt"],["attack_navigator_layer.json","att&ck"]];
 $("#runs").innerHTML=(j.runs||[]).slice(0,40).map(r=>{
  const b="evidence/"+r.name+"/";
  const links=FMT.filter(([f])=>r.files[f]).map(([f,l])=>{
    const blank=(f.endsWith(".csv")||f.endsWith(".xlsx"))?"":"target=_blank ";
    const pri=(f==="report.html")?" class=primary":"";
    return `<a ${blank}href="${b}${f}"${pri}>${l}</a>`;}).join("");
  return `<div class=runrow><span class=rn>${esc(r.name)}</span>`
   +(links?`<span class=rlinks>${links}</span>`:`<span class=nolink>no summary</span>`)+`</div>`;
 }).join("")||"—";
}

$("#roe").addEventListener("change",syncRoe);
$("#modeseg").addEventListener("click",e=>{if(!e.target.dataset.v)return;
 MODE=e.target.dataset.v;$$("#modeseg button").forEach(b=>b.classList.toggle("on",b.dataset.v===MODE));renderPostureMap();});
$$("[data-preset]").forEach(b=>b.addEventListener("click",()=>applyPreset(b.dataset.preset)));
$("#runbtn").addEventListener("click",startRun);
$("#stopbtn").addEventListener("click",()=>fetch("api/run/"+$("#stopbtn").dataset.id+"/stop",{method:"POST"}));
// --- three-way tab switch (Results / Live log / History) ---
const TABS=[["#tabRes","#paneRes"],["#tabLog","#paneLog"],["#tabHist","#paneHist"]];
function showTab(tab){TABS.forEach(([t,p])=>{const on=(t===tab);
  $(t).classList.toggle("on",on);$(t).setAttribute("aria-selected",on?"true":"false");$(p).classList.toggle("hidden",!on);});
  if(tab==="#tabHist") loadHistory();}
TABS.forEach(([t])=>$(t).addEventListener("click",()=>showTab(t)));
["#fq","#fverdict","#fcat","#ftarget"].forEach(s=>$(s).addEventListener("input",()=>renderRows()));
$$("#restable thead th").forEach(th=>th.addEventListener("click",()=>{
 const c=th.dataset.col; if(!c)return;
 SORT.dir=(SORT.col===c)?-SORT.dir:1; SORT.col=c; renderRows();}));
$$("#paneRes .exp button").forEach(b=>b.addEventListener("click",()=>exportRows(b.dataset.exp)));
$("#dclose").addEventListener("click",closeDrawer);
$("#scrim").addEventListener("click",closeDrawer);
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();});

// --- History: cross-run query over the SQLite index (derived from evidence/) ---
let HROWS=[], HSORT={col:"ts",dir:-1};
async function loadHistory(){
 const p=new URLSearchParams();
 const q=$("#hq").value.trim(); if(q)p.set("q",q);
 if($("#hverdict").value)p.set("verdict",$("#hverdict").value);
 if($("#htarget").value)p.set("target_ip",$("#htarget").value);
 if($("#hsite").value)p.set("site_id",$("#hsite").value);
 p.set("limit","2000");
 $("#histbody").innerHTML="<tr><td colspan=9 class=dim>loading…</td></tr>";
 try{
  const j=await (await fetch("api/query?"+p.toString())).json();
  if(j.error){$("#histbody").innerHTML="<tr><td colspan=9 class=dim>"+esc(j.error)+"</td></tr>";return;}
  HROWS=j.rows||[]; renderHistRoll(j.stats||{}); syncHistFilters(j.stats||{}); renderHist();
 }catch(err){$("#histbody").innerHTML="<tr><td colspan=9 class=dim>error: "+esc(""+err)+"</td></tr>";}
}
function renderHistRoll(stats){
 const o=stats.overall||{};
 $("#histroll").innerHTML=(BOOT.verdict_order||[]).filter(v=>o[v]).map(v=>{
  const c=vcolor(v);
  return `<span class=hr><i style="background:${c}"></i>${esc(v)} <b>${o[v]}</b></span>`;}).join("")
  +` <span class="hr runs"><i></i>runs <b>${stats.runs||0}</b></span>`;
}
function syncHistFilters(stats){
 const add=(sel,vals)=>{const cur=sel.value,have=new Set([...sel.options].map(o=>o.value));
  [...vals].filter(Boolean).sort().forEach(v=>{if(!have.has(v)){const o=document.createElement("option");o.value=o.textContent=v;sel.appendChild(o);}});sel.value=cur;};
 add($("#hverdict"), new Set(HROWS.map(r=>r.verdict)));
 add($("#htarget"),  new Set(HROWS.map(r=>r.target_ip)));
 add($("#hsite"),    new Set(HROWS.map(r=>r.site_id)));
}
function renderHist(){
 const rows=HROWS.slice(), c=HSORT.col, d=HSORT.dir;
 rows.sort((a,b)=>{let x=(""+(a[c]||"")).toLowerCase(),y=(""+(b[c]||"")).toLowerCase();return x<y?-d:x>y?d:0;});
 const tb=$("#histbody"); tb.innerHTML="";
 rows.forEach(r=>{const col=vcolor(r.verdict);
  const tr=document.createElement("tr");
  tr.innerHTML=`<td class=mono>${esc((r.ts||"").replace("T"," ").slice(5,19))}</td>`
   +`<td><span class=vchip style="color:${col}"><span class=d></span><span class=t>${esc(r.verdict)}</span></span></td>`
   +`<td class=mono>${esc(r.target_ip)}</td><td>${esc(r.attack)}</td><td class=dim>${esc(r.category)}</td>`
   +`<td class=mono>${esc(r.mitre)}</td><td class=mono>${esc(r.cwe)}</td>`
   +`<td class=mono>${esc(r.site_id||"")}</td><td class=mono title="${esc(r.run_id)}">${esc((r.run_id||"").replace(/^run_/,""))}</td>`;
  tb.appendChild(tr);});
 $("#histcount").textContent=rows.length+" rows";
 $$("#histtable thead th").forEach(th=>{const a=th.querySelector(".ar"); if(a)a.remove();
  if(th.dataset.hcol===HSORT.col){const s=document.createElement("span");s.className="ar";s.textContent=HSORT.dir>0?"▲":"▼";th.appendChild(s);}});
}
["#hq","#hverdict","#htarget","#hsite"].forEach(s=>$(s).addEventListener("input",loadHistory));
$$("#histtable thead th").forEach(th=>th.addEventListener("click",()=>{
 const c=th.dataset.hcol; if(!c)return; HSORT.dir=(HSORT.col===c)?-HSORT.dir:1; HSORT.col=c; renderHist();}));
$("#reindex").addEventListener("click",async()=>{
 $("#reindex").textContent="reindexing…";
 try{await fetch("api/reindex",{method:"POST"});}catch(e){}
 $("#reindex").textContent="reindex"; loadHistory();});
$$("#paneHist [data-hexp]").forEach(b=>b.addEventListener("click",()=>{
 const cols=["ts","verdict","target_ip","attack","category","mitre","cwe","site_id","run_id"];
 let data,ext;
 if(b.dataset.hexp==="json"){data=JSON.stringify(HROWS,null,1);ext="json";}
 else{const qq=s=>'"'+(""+(s==null?"":s)).replace(/"/g,'""')+'"';
   data=cols.join(",")+"\n"+HROWS.map(r=>cols.map(c=>qq(r[c])).join(",")).join("\n");ext="csv";}
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([data],{type:"text/"+ext}));
 a.download="history-"+Date.now()+"."+ext;a.click();URL.revokeObjectURL(a.href);}));
boot();
</script>
</body></html>"""


def main():
    global TOKEN
    ap = argparse.ArgumentParser(description="Web front-end for the Control Validation Harness.")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0 = all interfaces)")
    ap.add_argument("--port", type=int, default=8080, help="bind port (default 8080)")
    ap.add_argument("--token", default=os.environ.get("HARNESS_WEB_TOKEN"),
                    help="require this token (?token= or X-Token header) on every request")
    args = ap.parse_args()
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
