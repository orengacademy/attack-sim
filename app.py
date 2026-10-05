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

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")

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


# ---------------------------------------------------------------------------
# data helpers
# ---------------------------------------------------------------------------
def _ports_str(meta):
    out = []
    for s in meta.get("ports", []) or []:
        if isinstance(s, (list, tuple)):
            pr, pp = s
            out.append(f"{pp}/{pr}" if pp is not None else str(pr))
        else:
            out.append(str(s))
    return ", ".join(out)


def _module_json(m):
    me = m.META
    return {
        "id": me["id"], "name": me["name"], "category": me.get("category", ""),
        "mitre": me.get("mitre", []), "cwe": me.get("cwe", []),
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
        targets = []
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
        "modules": mods, "presets": presets, "targets": targets,
        "verdict_order": _VORDER,
        "verdict_colors": {v: _VCOLOR.get(v, "#8b90a6") for v in _VORDER},
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
            "ports": _ports_str(meta) or "—"}


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
              "roots": [], "error": None, "started": time.time()}
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
    mode = "whitebox" if params.get("mode") == "whitebox" else "blackbox"
    site_id = (params.get("site_id") or "").strip() or None
    active = bool(params.get("active"))
    debug = bool(params.get("debug"))
    creds = {k: v for k, v in (params.get("creds") or {}).items() if v}
    source = (params.get("source") or "").strip() or None
    appliance = (params.get("appliance") or "").strip() or None   # dual-path 2nd leg
    cloud = bool(params.get("cloud"))
    try:
        from modules import _portpatch
    except Exception:
        _portpatch = None

    emit({"type": "started", "run_id": run_id, "targets": targets,
          "mode": mode, "iterations": iters, "workers": workers,
          "count": len(mods), "site_id": site_id or "", "active": active})
    try:
        for ti, target in enumerate(targets, 1):
            emit({"type": "target", "index": ti, "total": len(targets), "target": target})
            if _portpatch is not None:
                if cloud:
                    try:
                        _portpatch.CUSTOM_PORT_TARGETS[target] = {
                            445: int(params.get("smb_port") or 4445),
                            135: int(params.get("rpc_port") or 1135),
                            22: int(params.get("ssh_port") or 22)}
                    except (TypeError, ValueError):
                        _portpatch.CUSTOM_PORT_TARGETS[target] = {445: 4445, 135: 1135, 22: 22}
                else:
                    _portpatch.CUSTOM_PORT_TARGETS.pop(target, None)
            runner = core.Runner(
                target, appliance,
                on_log=lambda m: emit({"type": "log", "line": str(m)}),
                on_progress=lambda c, t: emit({"type": "progress", "done": c, "total": t}),
                on_output=lambda aid, name, it, raw: emit({"type": "output", "id": aid, "name": name, "it": it}),
                on_status=lambda aid, name, it, b, v, _t=target: emit(_status_event(aid, name, it, b, v, _t)))
            st["runner"] = runner
            runner.concurrency = workers
            if wait_unblock > 0:
                runner.wait_unblock = wait_unblock
            runner.ctx.allow_active = active
            runner.ctx.debug = debug
            for k, v in creds.items():
                runner.ctx.creds[k] = v
            if source:
                runner.ctx.source_ip = source
            try:
                core.remember_target(target, source=source, cloud=cloud,
                                     mode=mode, site_id=site_id, **creds)
            except Exception:
                pass
            ev = core.Evidence(label=(target if len(targets) > 1 else None))
            root = runner.run(mods, iters, ev, mode=mode, site_id=site_id)
            rel = os.path.relpath(root, HERE)
            st["roots"].append({"target": target, "root": rel})
            emit({"type": "target_done", "target": target, "root": rel})
            if getattr(runner, "_stop", False):
                break
            if _portpatch is not None and cloud:
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
        return self._json({"error": "not found"}, 404)

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
               for f in ("report.html", "report.txt", "summary.json", "summary.csv")}
        out.append({"name": name, "mtime": os.path.getmtime(p), "files": has})
    return out


# ---------------------------------------------------------------------------
# the single-page dashboard (served as a plain string — no interpolation)
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Control Validation Harness — Web</title>
<style>
:root{
 --bg:#0d1117; --panel:#161b22; --panel2:#1c2230; --surf:#21262d; --line:#2b313c;
 --fg:#e6edf3; --muted:#8b949e; --accent:#7c6cf0; --accent2:#9385f4;
 --red:#e5484d; --orange:#f5a524; --green:#30a46c; --blue:#4493f8; --purple:#a371f7; --amber:#e2a336;
}
*{box-sizing:border-box} html,body{margin:0}
body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
a{color:var(--blue);text-decoration:none} a:hover{text-decoration:underline}
.wrap{max-width:1500px;margin:0 auto;padding:16px}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px}
header h1{font-size:18px;margin:0;font-weight:700;letter-spacing:.2px}
.badge{background:var(--surf);color:var(--muted);font-size:12px;padding:2px 9px;border-radius:20px;border:1px solid var(--line)}
.grow{flex:1}
button{font:inherit;border:0;border-radius:8px;padding:8px 14px;background:var(--surf);color:var(--fg);cursor:pointer;border:1px solid var(--line)}
button:hover{background:var(--panel2)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
button.primary:hover{background:var(--accent2)}
button.danger{background:#45202b;border-color:#5b2733;color:#ffb4bd}
button:disabled{opacity:.5;cursor:not-allowed}
.bento{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}
.card h2{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
.col3{grid-column:span 3} .col4{grid-column:span 4} .col5{grid-column:span 5}
.col6{grid-column:span 6} .col7{grid-column:span 7} .col8{grid-column:span 8} .col12{grid-column:span 12}
@media(max-width:1100px){.col3,.col4,.col5,.col6,.col7,.col8{grid-column:span 12}}
label{display:block;font-size:12px;color:var(--muted);margin:8px 0 3px}
input,select,textarea{width:100%;background:var(--surf);border:1px solid var(--line);color:var(--fg);
 border-radius:8px;padding:7px 9px;font:inherit}
textarea{resize:vertical;min-height:52px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap} .row>*{flex:1}
.inline{display:flex;align-items:center;gap:7px} .inline input[type=checkbox]{width:auto}
.seg{display:flex;background:var(--surf);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.seg button{border:0;border-radius:0;background:transparent;flex:1;padding:7px}
.seg button.on{background:var(--accent);color:#fff}
.meters .bar{display:flex;align-items:center;gap:9px;margin:5px 0;font-size:12px}
.meters .lbl{width:118px;font-weight:600} .meters .track{flex:1;height:9px;background:var(--surf);border-radius:5px;overflow:hidden}
.meters .track>span{display:block;height:100%;width:0;transition:width .3s} .meters .cnt{width:46px;text-align:right;color:var(--muted)}
.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.kpi{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px;text-align:center}
.kpi b{display:block;font-size:22px} .kpi span{font-size:11px;color:var(--muted)}
.progress{height:6px;background:var(--surf);border-radius:4px;overflow:hidden;margin-top:8px}
.progress>span{display:block;height:100%;width:0;background:var(--accent);transition:width .25s}
.mods{max-height:360px;overflow:auto;padding-right:4px}
.catgrp{margin-bottom:8px}
.catgrp .ct{font-size:11px;color:var(--blue);font-weight:700;margin:8px 0 4px;position:sticky;top:0;background:var(--panel);padding:2px 0}
.chip{display:flex;align-items:center;gap:7px;padding:4px 6px;border-radius:7px}
.chip:hover{background:var(--panel2)} .chip input{width:auto}
.chip .nm{flex:1} .chip .mi{color:var(--muted);font-size:11px;font-family:ui-monospace,monospace}
.tag{font-size:9px;padding:1px 5px;border-radius:5px;background:var(--panel2);border:1px solid var(--line);color:var(--muted)}
.tag.new{background:#2a1d3a;border-color:#52307a;color:#c89bff}
.tag.root{background:#3a2a16;border-color:#6a4a16;color:#f0c879}
.log{height:300px;overflow:auto;background:#0b0e14;border:1px solid var(--line);border-radius:10px;
 padding:9px 11px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;white-space:pre-wrap}
.log .finding{color:var(--red)} .log .good{color:var(--green)} .log .info{color:var(--blue)}
.log .warn{color:var(--amber)} .log .hdr{color:var(--accent2)} .log .muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--panel);cursor:pointer}
.tblwrap{max-height:360px;overflow:auto}
.pill{color:#fff;padding:1px 8px;border-radius:9px;font-size:11px;font-weight:600;white-space:nowrap}
.detail{color:var(--muted);max-width:420px}
.tabs{display:flex;gap:6px;margin-bottom:8px}
.tabs button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.hidden{display:none}
.note{font-size:11px;color:var(--muted);margin-top:6px}
.runs a{display:inline-block;margin-right:8px}
details summary{cursor:pointer;color:var(--muted);font-size:12px;margin:6px 0}
</style></head><body><div class=wrap>

<header>
 <h1>Control Validation Harness</h1>
 <span class=badge id=ver>web</span>
 <span class=badge id=polname></span>
 <span class=grow></span>
 <span class=badge id=modcount></span>
 <button class=primary id=runbtn>▶ RUN</button>
 <button class=danger id=stopbtn disabled>■ STOP</button>
</header>

<div class=bento>

 <!-- Target & run -->
 <div class="card col4">
  <h2>Target &amp; run</h2>
  <label>Targets (one per line, or comma-separated)</label>
  <textarea id=targets placeholder="159.223.35.108&#10;167.71.222.169"></textarea>
  <label>Posture</label>
  <div class=seg id=modeseg>
    <button data-v=blackbox class=on>Black-box</button>
    <button data-v=whitebox>White-box (allow-all)</button>
  </div>
  <div class=row>
    <div><label>Iterations</label><input id=iters type=number min=1 max=20 value=1></div>
    <div><label>Workers</label><input id=workers type=number min=1 max=16 value=4></div>
    <div><label>Wait-unblock s</label><input id=wait type=number min=0 value=0></div>
  </div>
  <div class=row>
    <div><label>Site ID</label><input id=site placeholder="ORG2026-70"></div>
    <div><label>Source IP</label><input id=source placeholder="(egress bind)"></div>
  </div>
  <div class=row>
    <div><label>Appliance IP (dual-path)</label><input id=appliance placeholder="through-appliance IP — blank = single-target"></div>
  </div>
  <div class=row style="margin-top:8px">
    <label class=inline><input type=checkbox id=active> Active establishment</label>
    <label class=inline><input type=checkbox id=debug> Debug</label>
  </div>
  <details>
    <summary>Cloud NAT ports &amp; credentials</summary>
    <label class=inline><input type=checkbox id=cloud> Cloud target (NAT'd ports)</label>
    <div class=row>
      <div><label>SMB</label><input id=smb value=4445></div>
      <div><label>RPC</label><input id=rpc value=1135></div>
      <div><label>SSH</label><input id=sshp value=22></div>
    </div>
    <div class=row><div><label>Domain</label><input id=domain></div><div><label>DC user</label><input id=dcuser></div></div>
    <div class=row><div><label>DC pass</label><input id=dcpass type=password></div></div>
    <div class=row><div><label>SSH user</label><input id=sshuser></div><div><label>SSH pass</label><input id=sshpass type=password></div></div>
    <div class=note id=crednote></div>
  </details>
  <label class=inline style="margin-top:10px"><input type=checkbox id=roe> Rules-of-engagement confirmed</label>
  <div class=note>Runs REAL attacks. Keep this on a trusted lab segment.</div>
 </div>

 <!-- Verdict distribution -->
 <div class="card col4">
  <h2>Verdict distribution</h2>
  <div class=meters id=meters></div>
  <div class=kpis style="margin-top:10px">
    <div class=kpi><b id=k_find style="color:var(--red)">0</b><span>findings</span></div>
    <div class=kpi><b id=k_det style="color:var(--orange)">0</b><span>detected</span></div>
    <div class=kpi><b id=k_block style="color:var(--green)">0</b><span>blocked</span></div>
  </div>
  <div class=progress><span id=prog></span></div>
  <div class=note id=runmeta>Idle.</div>
 </div>

 <!-- Attacks -->
 <div class="card col4">
  <h2>Attacks <span id=selcount class=badge></span></h2>
  <div class=row style="margin-bottom:6px">
    <button data-preset=original>Original</button>
    <button data-preset=attack_sim>USS A–G</button>
    <button data-preset=added>Added</button>
    <button data-preset=all>All</button>
    <button data-preset=none>Clear</button>
  </div>
  <div class=mods id=mods></div>
 </div>

 <!-- Live + results -->
 <div class="card col12">
  <div class=tabs>
    <button id=tab_res class=on>Results</button>
    <button id=tab_log>Live log</button>
    <span class=grow></span>
    <span class=badge id=evlinks></span>
  </div>
  <div id=pane_res>
    <div class=tblwrap><table id=restbl>
      <thead><tr><th>#</th><th>Verdict</th><th>Module</th><th>Category</th><th>Target</th>
      <th>Ports</th><th>MITRE</th><th>It</th><th>Detail</th></tr></thead>
      <tbody></tbody></table></div>
  </div>
  <div id=pane_log class=hidden><div class=log id=log></div></div>
 </div>

 <!-- Recent runs -->
 <div class="card col12">
  <h2>Recent evidence</h2>
  <div class=runs id=runs>—</div>
 </div>

</div></div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let BOOT=null, MODE="blackbox", ES=null, COUNTS={}, TOTAL=0, RESROWS=0;

function esc(s){return (s||"").replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

async function boot(){
  BOOT=await (await fetch("api/bootstrap")).json();
  $("#ver").textContent="v"+BOOT.version+(BOOT.engine?(" ("+BOOT.engine+")"):"");
  $("#polname").textContent=BOOT.policy||"";
  $("#modcount").textContent=BOOT.modules.length+" modules";
  $("#workers").value=BOOT.workers;
  $("#roe").checked=BOOT.roe;
  const cl=BOOT.creds_loaded;
  $("#crednote").textContent="Loaded: "+Object.entries(cl).map(([k,v])=>k+" "+(v?"✓":"—")).join("  ");
  if(BOOT.targets&&BOOT.targets.length) $("#targets").value=BOOT.targets.join("\n");
  renderMeters(); renderMods(); applyPreset("original"); loadRuns();
}

function renderMeters(){
  const m=$("#meters"); m.innerHTML="";
  BOOT.verdict_order.forEach(v=>{
    const c=BOOT.verdict_colors[v]||"#8b949e";
    m.insertAdjacentHTML("beforeend",
     `<div class=bar><span class=lbl style="color:${c}">${v}</span>`
     +`<span class=track><span id="mt_${v}" style="background:${c}"></span></span>`
     +`<span class=cnt id="mc_${v}">0</span></div>`);
  });
}
function renderMods(){
  const host=$("#mods"); host.innerHTML="";
  const byCat={};
  BOOT.modules.forEach(m=>{(byCat[m.category]=byCat[m.category]||[]).push(m);});
  Object.keys(byCat).sort().forEach(cat=>{
    const g=document.createElement("div"); g.className="catgrp";
    g.innerHTML=`<div class=ct>${esc(cat)}</div>`;
    byCat[cat].forEach(m=>{
      const tags=(m.added?'<span class="tag new">NEW</span>':'')+(m.needs_root?'<span class="tag root">root</span>':'');
      g.insertAdjacentHTML("beforeend",
       `<label class=chip title="${esc(m.control||'')}"><input type=checkbox data-id="${m.id}">`
       +`<span class=nm>${esc(m.name)} ${tags}</span>`
       +`<span class=mi>${esc(m.mitre.join(", "))}</span></label>`);
    });
    host.appendChild(g);
  });
  host.addEventListener("change",updSel);
}
function applyPreset(p){
  const ids=p==="none"?[]:(BOOT.presets[p]||[]);
  $$("#mods input").forEach(cb=>cb.checked=ids.includes(cb.dataset.id));
  updSel();
}
function updSel(){ $("#selcount").textContent=$$("#mods input:checked").length+" sel"; }
function selectedIds(){ return $$("#mods input:checked").map(cb=>cb.dataset.id); }

function logLine(t){
  const low=t.toLowerCase(); let cls="";
  if(low.includes("success")||low.includes("[finding]")) cls="finding";
  else if(low.includes("no-service")) cls="info";
  else if(low.includes("blocked")||low.includes("control working")) cls="good";
  else if(low.includes("[warn]")||low.includes("[error]")||low.includes("no-result")||low.includes("auth-failed")) cls="warn";
  else if(t.startsWith("===")||t.startsWith("[")||t.startsWith("Platform")||t.startsWith("Recon")||t.startsWith("Preflight")) cls="hdr";
  const d=document.createElement("div"); if(cls)d.className=cls; d.textContent=t;
  const L=$("#log"); L.appendChild(d); L.scrollTop=L.scrollHeight;
}
function addRow(e){
  const c=BOOT.verdict_colors[e.verdict]||"#8b949e";
  const tb=$("#restbl tbody");
  const tr=document.createElement("tr");
  tr.innerHTML=`<td>${++RESROWS}</td><td><span class=pill style="background:${c}">${e.verdict}</span></td>`
    +`<td>${esc(e.name)}</td><td style="color:var(--muted)">${esc(e.category)}</td>`
    +`<td style="color:var(--muted)">${esc(e.target)}</td><td style="color:var(--muted)">${esc(e.ports)}</td>`
    +`<td style="color:var(--muted)">${esc(e.mitre)}</td><td>${e.it}</td>`
    +`<td class=detail>${esc(e.detail)}</td>`;
  tb.appendChild(tr);
  COUNTS[e.verdict]=(COUNTS[e.verdict]||0)+1; refreshCounts();
}
function refreshCounts(){
  const tot=Object.values(COUNTS).reduce((a,b)=>a+b,0)||1;
  BOOT.verdict_order.forEach(v=>{
    const n=COUNTS[v]||0;
    const mt=$("#mt_"+v), mc=$("#mc_"+v);
    if(mt)mt.style.width=(100*n/tot)+"%"; if(mc)mc.textContent=n;
  });
  $("#k_find").textContent=(COUNTS["SUCCESS"]||0)+(COUNTS["PASSED"]||0);
  $("#k_det").textContent=COUNTS["DETECTED"]||0;
  $("#k_block").textContent=COUNTS["BLOCKED"]||0;
}

function startRun(){
  const targets=$("#targets").value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
  const body={
    targets, module_ids:selectedIds(), mode:MODE,
    iterations:+$("#iters").value, workers:+$("#workers").value,
    wait_unblock:+$("#wait").value, site_id:$("#site").value, source:$("#source").value,
    appliance:$("#appliance").value,
    active:$("#active").checked, debug:$("#debug").checked, confirm_roe:$("#roe").checked,
    cloud:$("#cloud").checked, smb_port:+$("#smb").value, rpc_port:+$("#rpc").value, ssh_port:+$("#sshp").value,
    creds:{domain:$("#domain").value,dc_user:$("#dcuser").value,dc_pass:$("#dcpass").value,
           ssh_user:$("#sshuser").value,ssh_pass:$("#sshpass").value}
  };
  fetch("api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
   .then(r=>r.json()).then(j=>{
     if(j.error){alert(j.error);return;}
     // reset
     COUNTS={};RESROWS=0;$("#restbl tbody").innerHTML="";$("#log").innerHTML="";refreshCounts();
     $("#evlinks").textContent="";$("#prog").style.width="0";
     $("#runbtn").disabled=true;$("#stopbtn").disabled=false;$("#stopbtn").dataset.id=j.run_id;
     stream(j.run_id);
   });
}
function stream(id){
  if(ES)ES.close();
  ES=new EventSource("api/run/"+id+"/stream");
  ES.onmessage=ev=>{
    const e=JSON.parse(ev.data);
    if(e.type==="log") logLine(e.line);
    else if(e.type==="status"){ addRow(e); }
    else if(e.type==="progress"){ $("#prog").style.width=(e.total?100*e.done/e.total:0)+"%"; }
    else if(e.type==="started"){ $("#runmeta").textContent=`Running ${e.count} module(s) · ${e.mode} · ${e.iterations} it · ${e.workers} workers`+(e.site_id?` · ${e.site_id}`:"")+(e.active?" · ACTIVE":""); }
    else if(e.type==="target"){ logLine(`\n==== TARGET ${e.index}/${e.total}: ${e.target} ====`); }
    else if(e.type==="target_done"){ showEvidence(e.root); }
    else if(e.type==="done"){ finish(e.roots); }
    else if(e.type==="error"){ logLine("[ERROR] "+e.error); finish(e.roots||[]); }
  };
  ES.onerror=()=>{};
}
function showEvidence(root){
  const base="evidence/"+root.replace(/^evidence\//,"")+"/";
  $("#evlinks").innerHTML="Evidence: "
   +`<a target=_blank href="${base}report.html">report.html</a> · `
   +`<a target=_blank href="${base}summary.json">summary.json</a> · `
   +`<a target=_blank href="${base}report.txt">report.txt</a>`;
}
function finish(roots){
  $("#runbtn").disabled=false;$("#stopbtn").disabled=true;
  $("#runmeta").textContent="Done. "+Object.entries(COUNTS).map(([k,v])=>k+" "+v).join(" · ");
  if(ES)ES.close(); loadRuns();
}
async function loadRuns(){
  const j=await (await fetch("api/runs")).json();
  $("#runs").innerHTML=(j.runs||[]).map(r=>{
    const b="evidence/"+r.name+"/";
    const links=["report.html","summary.json","report.txt"].filter(f=>r.files[f])
      .map(f=>`<a target=_blank href="${b}${f}">${f.split('.').pop()}</a>`).join(" ");
    return `<div style="margin:3px 0"><b>${r.name}</b> ${links||'<span style="color:var(--muted)">(no summary)</span>'}</div>`;
  }).join("")||"—";
}

$("#modeseg").addEventListener("click",e=>{
  if(!e.target.dataset.v)return;
  MODE=e.target.dataset.v; $$("#modeseg button").forEach(b=>b.classList.toggle("on",b.dataset.v===MODE));
});
$$("[data-preset]").forEach(b=>b.addEventListener("click",()=>applyPreset(b.dataset.preset)));
$("#runbtn").addEventListener("click",startRun);
$("#stopbtn").addEventListener("click",()=>fetch("api/run/"+$("#stopbtn").dataset.id+"/stop",{method:"POST"}));
$("#tab_res").addEventListener("click",()=>{$("#tab_res").classList.add("on");$("#tab_log").classList.remove("on");$("#pane_res").classList.remove("hidden");$("#pane_log").classList.add("hidden");});
$("#tab_log").addEventListener("click",()=>{$("#tab_log").classList.add("on");$("#tab_res").classList.remove("on");$("#pane_log").classList.remove("hidden");$("#pane_res").classList.add("hidden");});
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
