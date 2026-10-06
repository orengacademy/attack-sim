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
               for f in ("report.html", "report.txt", "summary.json", "summary.csv")}
        out.append({"name": name, "mtime": os.path.getmtime(p), "files": has})
    return out


# ---------------------------------------------------------------------------
# the single-page dashboard (served as a plain string — no interpolation)
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Control Validation Harness</title>
<link rel=preconnect href="https://fonts.googleapis.com">
<link rel=preconnect href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel=stylesheet>
<style>
:root{
 --base:#0c1014; --base2:#0f151b; --surf:#141c24; --surf2:#1a242e;
 --line:#212d37; --line2:#30424f; --hair:#1a242d;
 --fg:#e7eef5; --muted:#8597a8; --faint:#56687a;
 --edge:#79e3e8;                 /* cold cyan: interactive affordance ONLY */
 /* signal palette = the only colour on the page (verdict semantics) */
 --got:#ff5a5a; --det:#f5a33c; --blk:#3fd08a; --svc:#4c8dff; --inc:#a98bff; --skip:#5f7083;
 --ui:'Space Grotesk',ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;
 --mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--base);color:var(--fg);font-family:var(--ui);font-size:14px;line-height:1.5;
 -webkit-font-smoothing:antialiased}
a{color:var(--edge);text-decoration:none} a:hover{text-decoration:underline}
::selection{background:#28414a;color:#fff}
:focus-visible{outline:2px solid var(--edge);outline-offset:1px;border-radius:3px}

/* ---- scaffolding: topbar + console (rail | theatre) ---- */
.shell{min-height:100%;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:18px;padding:14px 22px;border-bottom:1px solid var(--line);
 background:linear-gradient(180deg,var(--base2),var(--base))}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.mark{width:30px;height:30px;color:var(--edge);flex:none}
.title{font-weight:600;font-size:17px;letter-spacing:-.01em}
.sub{display:flex;gap:0;color:var(--muted);font-size:12px;font-family:var(--mono);margin-top:1px;flex-wrap:wrap}
.sub>span{padding:0 10px;border-left:1px solid var(--line2)} .sub>span:first-child{padding-left:0;border-left:0}
.cmd{margin-left:auto;display:flex;align-items:center;gap:12px}
.roe{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;cursor:pointer;user-select:none}
.btn{font-family:var(--ui);font-weight:600;font-size:14px;border:1px solid var(--line2);background:var(--surf);
 color:var(--fg);border-radius:7px;padding:9px 18px;cursor:pointer;transition:background .12s,border-color .12s}
.btn:hover{background:var(--surf2)}
.btn.run{background:var(--fg);color:#0a0e12;border-color:var(--fg)}
.btn.run:hover{background:#fff} .btn.run:disabled{background:var(--surf2);color:var(--faint);border-color:var(--line);cursor:not-allowed}
.btn.stop{color:var(--got);border-color:#4a2630} .btn.stop:hover{background:#2a1419}
.btn.stop:disabled{color:var(--faint);border-color:var(--line);background:transparent;cursor:not-allowed}

.console{flex:1;display:grid;grid-template-columns:minmax(330px,380px) 1fr;gap:0;min-height:0}
.rail{border-right:1px solid var(--line);overflow:auto;background:var(--base)}
.theatre{overflow:auto;background:var(--base2);min-width:0}
@media(max-width:920px){.console{grid-template-columns:1fr}.rail{border-right:0;border-bottom:1px solid var(--line)}}

/* ---- rail: grouped controls, hairline-separated (NOT identical cards) ---- */
.group{padding:16px 20px;border-bottom:1px solid var(--hair)}
.glabel{font-weight:600;font-size:13px;margin:0 0 10px;letter-spacing:-.01em}
.field{margin-bottom:10px} .field:last-child{margin-bottom:0}
.field>label{display:block;font-size:12px;color:var(--muted);margin:0 0 4px}
input[type=text],input[type=password],input[type=number],textarea,select{width:100%;background:var(--base2);
 border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:8px 10px;font:inherit;font-size:13px}
input:focus,textarea:focus{border-color:var(--line2);background:var(--surf)}
textarea{font-family:var(--mono);font-size:12.5px;resize:vertical;min-height:50px}
.rowf{display:flex;gap:8px} .rowf>*{flex:1;min-width:0}
.chk{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--fg);cursor:pointer}
.chk input{accent-color:var(--edge)}
.mini{font-size:11.5px;color:var(--faint);margin-top:6px;line-height:1.45}
details{margin-top:8px} details>summary{cursor:pointer;color:var(--muted);font-size:12px;list-style:none;
 padding:4px 0;user-select:none} details>summary::before{content:'+ ';color:var(--edge)} details[open]>summary::before{content:'– '}

/* posture segmented control */
.seg{display:flex;border:1px solid var(--line);border-radius:7px;overflow:hidden;background:var(--base2)}
.seg button{flex:1;border:0;background:transparent;color:var(--muted);font:inherit;font-size:12.5px;padding:8px;cursor:pointer}
.seg button.on{background:var(--surf2);color:var(--fg);box-shadow:inset 0 -2px 0 var(--edge)}

/* prefill readout */
.loaded{display:flex;flex-wrap:wrap;gap:4px 12px;font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.loaded b{color:var(--fg);font-weight:500} .ok{color:var(--blk)} .no{color:var(--faint)}

/* preset controls + attack battery */
.presets{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.presets button{font:inherit;font-size:12px;border:1px solid var(--line);background:var(--base2);color:var(--muted);
 border-radius:20px;padding:4px 11px;cursor:pointer} .presets button:hover{color:var(--fg);border-color:var(--line2)}
.selcount{font-family:var(--mono);font-size:12px;color:var(--edge)}
.battery{max-height:420px;overflow:auto;margin:0 -4px}
.cat{margin:10px 0 2px;display:flex;align-items:center;gap:8px;position:sticky;top:0;background:var(--base);padding:4px}
.cat .cn{font-size:11px;color:var(--muted);font-weight:600} .cat .cl{flex:1;height:1px;background:var(--hair)}
.atk{display:flex;align-items:center;gap:9px;padding:5px 8px;border-radius:6px;cursor:pointer}
.atk:hover{background:var(--surf)} .atk input{accent-color:var(--edge);flex:none}
.atk .nm{flex:1;font-size:13px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.atk .mi{font-family:var(--mono);font-size:11px;color:var(--faint);flex:none;text-align:right;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.atk .mi .cwe{font-style:normal;color:var(--edge);opacity:.8}
.flag{font-family:var(--mono);font-size:9.5px;padding:0 4px;border:1px solid var(--line2);border-radius:3px;color:var(--muted);flex:none}
.flag.new{color:var(--inc);border-color:#3a2f55} .flag.root{color:var(--det);border-color:#4a3a1e}

/* ---- theatre: the signal hero ---- */
.hero{padding:20px 24px 16px;border-bottom:1px solid var(--line);display:grid;
 grid-template-columns:auto 1fr;gap:28px;align-items:center}
@media(max-width:620px){.hero{grid-template-columns:1fr;gap:14px}}
.tally{min-width:150px}
.big{font-family:var(--mono);font-weight:700;font-size:64px;line-height:.9;color:var(--got);letter-spacing:-.02em}
.big.zero{color:var(--faint)}
.biglabel{font-size:13px;color:var(--muted);margin-top:4px}
.subtally{display:flex;gap:16px;margin-top:12px;font-size:12.5px;color:var(--muted)}
.subtally .dot{width:8px;height:8px;border-radius:2px;display:inline-block;margin-right:6px;vertical-align:1px}
.spectrum{height:34px;display:flex;border-radius:5px;overflow:hidden;background:var(--base);border:1px solid var(--line)}
.spectrum i{display:block;height:100%;transition:width .35s ease}
.spectrum .empty{flex:1;display:flex;align-items:center;justify-content:center;color:var(--faint);font-size:12px;font-family:var(--mono)}
/* verdict key (glossary of every verdict label; chips also filter the table) */
.vkeywrap{margin:2px 24px 0;font-size:12px}
.vkeywrap summary{cursor:pointer;color:var(--muted);font-size:11.5px;padding:4px 0}
.vkey{display:flex;flex-wrap:wrap;gap:6px;padding:6px 0 2px}
.vkey .vk{display:flex;align-items:center;gap:7px;padding:4px 9px;border:1px solid var(--line);
 border-radius:6px;background:var(--base2);cursor:pointer;max-width:340px}
.vkey .vk:hover{border-color:var(--edge)} .vkey .vk.on{border-color:var(--edge);background:var(--surf)}
.vkey .vk .sw{width:9px;height:9px;border-radius:2px;flex:none}
.vkey .vk b{color:var(--fg);font-family:var(--mono);font-weight:500;font-size:11px}
.vkey .vk span{color:var(--muted);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:11px;font-size:12px;color:var(--muted)}
.legend .li{display:flex;align-items:center;gap:7px}
.legend .sw{width:9px;height:9px;border-radius:2px;flex:none}
.legend b{color:var(--fg);font-family:var(--mono);font-weight:500}

.progress{height:2px;background:var(--line)} .progress>i{display:block;height:100%;width:0;background:var(--edge);transition:width .25s}
.runmeta{padding:9px 24px;color:var(--muted);font-size:12.5px;font-family:var(--mono);border-bottom:1px solid var(--hair)}

/* results / log panel */
.panel{padding:0 0 10px}
.tabbar{display:flex;align-items:center;gap:4px;padding:10px 24px 8px}
.tab{font:inherit;font-size:13px;border:0;background:transparent;color:var(--muted);padding:5px 2px;margin-right:14px;cursor:pointer;border-bottom:2px solid transparent}
.tab.on{color:var(--fg);border-bottom-color:var(--edge)}
.evidence{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--muted)}
.wrap{max-height:48vh;overflow:auto;padding:0 12px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead th{position:sticky;top:0;background:var(--base2);text-align:left;font-weight:500;color:var(--muted);
 font-size:11.5px;padding:7px 10px;border-bottom:1px solid var(--line);cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{color:var(--text)} thead th .ar{opacity:.6;font-size:9px;margin-left:3px}
tbody td{padding:7px 10px;border-bottom:1px solid var(--hair);vertical-align:top}
tbody tr{cursor:pointer} tbody tr:hover{background:var(--surf)}
/* results toolbar: filter + export */
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:8px 24px}
.toolbar input,.toolbar select{width:auto;min-width:120px;padding:5px 8px;font-size:12px}
.toolbar input#fq{flex:1;min-width:180px}
.toolbar .rowcount{color:var(--muted);font-size:11.5px;font-family:var(--mono)}
.toolbar .exp{margin-left:auto;color:var(--muted);font-size:11.5px;display:flex;align-items:center;gap:4px}
.toolbar .exp button{padding:4px 9px;font-size:11px;background:var(--base2);border:1px solid var(--line);
 color:var(--text);border-radius:5px;cursor:pointer} .toolbar .exp button:hover{border-color:var(--edge)}
/* history rollup strip */
.histroll{display:flex;flex-wrap:wrap;gap:6px;padding:4px 24px 8px;font-size:11.5px}
.histroll .hr{display:flex;align-items:center;gap:6px;padding:3px 9px;border:1px solid var(--line);
 border-radius:14px;background:var(--base2);color:var(--muted)}
.histroll .hr i{width:8px;height:8px;border-radius:50%;flex:none} .histroll .hr b{color:var(--fg)}
/* raw-output drawer */
.drawer{position:fixed;top:0;right:0;width:min(760px,94vw);height:100vh;background:var(--base);z-index:40;
 border-left:1px solid var(--line2);box-shadow:-18px 0 50px rgba(0,0,0,.5);display:flex;flex-direction:column}
.drawer[hidden]{display:none}   /* class rule above would otherwise beat [hidden]'s display:none */
.drawer .dhead{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line)}
.drawer .dhead span{font-weight:600} .drawer .dhead button{padding:5px 12px;background:var(--base2);
 border:1px solid var(--line);color:var(--text);border-radius:5px;cursor:pointer}
.drawer .dmeta{padding:8px 18px;color:var(--muted);font-size:12px;font-family:var(--mono);border-bottom:1px solid var(--hair)}
.drawer .dbody{flex:1;overflow:auto;margin:0;padding:14px 18px;font-family:var(--mono);font-size:12px;
 white-space:pre-wrap;line-height:1.5;color:var(--text)}
.vcell{white-space:nowrap;font-weight:500} .vbar{width:3px;height:13px;border-radius:2px;display:inline-block;margin-right:8px;vertical-align:-2px}
.mono{font-family:var(--mono);color:var(--muted)} .dim{color:var(--muted)}
.detail{color:var(--muted);max-width:440px;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.log{height:46vh;overflow:auto;margin:0 24px;padding:10px 12px;background:var(--base);border:1px solid var(--line);
 border-radius:6px;font-family:var(--mono);font-size:12px;white-space:pre-wrap;line-height:1.55}
.log .c-got{color:var(--got)} .log .c-blk{color:var(--blk)} .log .c-svc{color:var(--svc)}
.log .c-det{color:var(--det)} .log .c-hdr{color:var(--edge)} .log .c-mut{color:var(--faint)}
.hidden{display:none}

.runsbar{padding:14px 24px;border-top:1px solid var(--hair);color:var(--muted);font-size:12.5px}
.runsbar h3{font-size:12px;font-weight:600;color:var(--fg);margin:0 0 8px}
.runrow{font-family:var(--mono);font-size:12px;padding:3px 0;display:flex;gap:12px;align-items:baseline}
.runrow b{color:var(--fg);font-weight:500}
.warnline{color:var(--det);font-size:11.5px;margin-top:10px;line-height:1.5}
</style></head>
<body><div class=shell>

<header class=topbar>
 <div class=brand>
  <svg class=mark viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=1.5 aria-hidden=true>
   <circle cx=12 cy=12 r=7.5/><path d="M12 1.5V6M12 18v4.5M1.5 12H6M18 12h4.5"/><circle cx=12 cy=12 r=1.8 fill=currentColor stroke=none/>
  </svg>
  <div>
   <div class=title>Control Validation Harness</div>
   <div class=sub id=subline><span>connecting…</span></div>
  </div>
 </div>
 <div class=cmd>
  <label class=roe><input type=checkbox id=roe> Rules of engagement confirmed</label>
  <button class="btn stop" id=stopbtn disabled>Stop</button>
  <button class="btn run" id=runbtn>Run battery</button>
 </div>
</header>

<main class=console>
 <!-- command rail -->
 <section class=rail>
  <div class=group>
   <h2 class=glabel>Targets</h2>
   <div class=field>
    <textarea id=targets placeholder="one host per line&#10;159.223.35.108&#10;167.71.222.169"></textarea>
   </div>
   <div class=field>
    <label>Posture</label>
    <div class=seg id=modeseg>
     <button data-v=blackbox class=on>Black-box</button>
     <button data-v=whitebox>White-box (allow-all)</button>
    </div>
   </div>
   <div class=rowf>
    <div class=field><label>Iterations</label><input id=iters type=number min=1 max=20 value=1></div>
    <div class=field><label>Workers</label><input id=workers type=number min=1 max=16 value=4></div>
    <div class=field><label>Wait-unblock s</label><input id=wait type=number min=0 value=0></div>
    <div class=field><label>Ban-expiry s</label><input id=banexp type=number min=0 value=300></div>
    <div class=field><label>Auto-retry</label><input id=autoretry type=number min=0 value=1></div>
   </div>
   <div class=rowf>
    <div class=field><label>Site</label><input id=site type=text placeholder="ORG2026-70"></div>
    <div class=field><label>Source IP</label><input id=source type=text placeholder="egress bind"></div>
   </div>
   <div class=field><label>Appliance IP — dual-path (blank = single-target)</label><input id=appliance type=text placeholder="run baseline + through-appliance and compare"></div>
   <label class=chk style="margin-top:4px"><input type=checkbox id=active> Active establishment (build real tunnels / pivots / exfil)</label>
   <label class=chk style="margin-top:6px"><input type=checkbox id=debug> Debug (verbose tools + timing)</label>
   <details id=credpanel>
    <summary>Credentials &amp; cloud NAT ports</summary>
    <label class=chk style="margin:8px 0"><input type=checkbox id=cloud> Cloud target (NAT'd SMB/RPC/SSH)</label>
    <div class=rowf>
     <div class=field><label>SMB</label><input id=smb type=number value=4445></div>
     <div class=field><label>RPC</label><input id=rpc type=number value=1135></div>
     <div class=field><label>SSH</label><input id=sshp type=number value=22></div>
    </div>
    <div class=rowf><div class=field><label>Domain</label><input id=domain type=text></div><div class=field><label>DC user</label><input id=dcuser type=text></div></div>
    <div class=field><label>DC password</label><input id=dcpass type=password></div>
    <div class=rowf><div class=field><label>SSH user</label><input id=sshuser type=text></div><div class=field><label>SSH password</label><input id=sshpass type=password></div></div>
    <div class=loaded id=loaded></div>
   </details>
  </div>

  <div class=group>
   <h2 class=glabel>Attack battery <span class=selcount id=selcount></span></h2>
   <div class=presets>
    <button data-preset=original>Original</button>
    <button data-preset=attack_sim>USS A–G</button>
    <button data-preset=added>Added</button>
    <button data-preset=all>All</button>
    <button data-preset=none>None</button>
   </div>
   <div class=battery id=battery></div>
  </div>
 </section>

 <!-- signal theatre -->
 <section class=theatre>
  <div class=hero>
   <div class=tally>
    <div class="big zero" id=findtally>0</div>
    <div class=biglabel>got through, undetected</div>
    <div class=subtally>
     <span><i class=dot style="background:var(--det)"></i><b id=t_det>0</b> detected</span>
     <span><i class=dot style="background:var(--blk)"></i><b id=t_blk>0</b> held</span>
    </div>
   </div>
   <div>
    <div class=spectrum id=spectrum><div class=empty>no results yet</div></div>
    <div class=legend id=legend></div>
   </div>
  </div>
  <div class=progress><i id=prog></i></div>
  <div class=runmeta id=runmeta>Idle — pick a target and run the battery.</div>

  <div class=panel>
   <div class=tabbar>
    <button class="tab on" id=tabRes>Results</button>
    <button class=tab id=tabLog>Live log</button>
    <button class=tab id=tabHist>History</button>
    <span class=evidence id=evidence></span>
   </div>
   <div id=paneRes>
    <details class=vkeywrap open><summary>Verdict key</summary><div class=vkey id=vkey></div></details>
    <div class=toolbar>
     <input id=fq type=text placeholder="filter… module / detail / ATT&amp;CK / CWE">
     <select id=fverdict><option value="">all verdicts</option></select>
     <select id=fcat><option value="">all categories</option></select>
     <select id=ftarget><option value="">all targets</option></select>
     <span class=rowcount id=rowcount></span>
     <span class=exp>export
      <button data-exp=csv>CSV</button>
      <button data-exp=json>JSON</button>
      <button data-exp=md>MD</button>
     </span>
    </div>
    <div class=wrap><table id=restable>
     <thead><tr>
      <th data-col=n>#</th><th data-col=verdict>Verdict</th><th data-col=name>Module</th>
      <th data-col=category>Category</th><th data-col=target>Target</th><th data-col=ports>Ports</th>
      <th data-col=mitre>ATT&amp;CK</th><th data-col=cwe>CWE</th><th data-col=it>It</th>
      <th data-col=detail>Detail</th></tr></thead>
     <tbody id=resbody></tbody></table></div>
   </div>
   <div id=paneLog class=hidden><div class=log id=log></div></div>
   <div id=paneHist class=hidden>
    <div class=toolbar>
     <input id=hq type=text placeholder="search all runs… module / detail / ATT&amp;CK / CWE">
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

  <!-- raw-output drawer (opens when a results row is clicked) -->
  <div id=drawer class=drawer hidden>
   <div class=dhead><span id=dtitle></span><button id=dclose>close</button></div>
   <div id=dmeta class=dmeta></div>
   <pre id=dbody class=dbody></pre>
  </div>

  <div class=runsbar>
   <h3>Recent evidence</h3>
   <div id=runs>—</div>
  </div>
 </section>
</main>
</div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let BOOT=null, MODE="blackbox", ES=null, COUNTS={}, RESN=0;
let ROWS=[], RUNID=null, SORT={col:"n",dir:1};   // results data model (filter/sort/export/click)
const KIND={SUCCESS:"got",DETECTED:"det",BLOCKED:"blk","NO-SERVICE":"svc",
 "AUTH-FAILED":"det","NO-RESULT":"det",INCONCLUSIVE:"inc",SKIPPED:"skip","PREREQ-MISSING":"skip"};
const HEX={got:"#ff5a5a",det:"#f5a33c",blk:"#3fd08a",svc:"#4c8dff",inc:"#a98bff",skip:"#5f7083"};
const LABEL={got:"got through",det:"detected / review",blk:"held",svc:"no service",inc:"inconclusive",skip:"skipped"};
const ORDER=["got","det","blk","svc","inc","skip"];
const esc=s=>(s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const kindOf=v=>KIND[v]||"det";

async function boot(){
 BOOT=await (await fetch("api/bootstrap")).json();
 const s=$("#subline"); s.innerHTML="";
 const bits=["v"+BOOT.version+(BOOT.engine?(" ("+BOOT.engine+")"):""), BOOT.policy||"no policy", BOOT.modules.length+" modules"];
 bits.forEach(t=>{const x=document.createElement("span");x.textContent=t;s.appendChild(x);});
 $("#workers").value=BOOT.workers; $("#roe").checked=BOOT.roe;
 const cl=BOOT.creds_loaded, L=$("#loaded"); L.innerHTML="";
 Object.entries(cl).forEach(([k,v])=>{const e=document.createElement("span");
  e.innerHTML=k.replace("_"," ")+" <b class="+(v?"ok":"no")+">"+(v?"set":"—")+"</b>";L.appendChild(e);});
 // prefill the global credential defaults (credentials.env / HARNESS_*)
 const C=BOOT.creds||{};
 $("#domain").value=C.domain||""; $("#dcuser").value=C.dc_user||""; $("#dcpass").value=C.dc_pass||"";
 $("#sshuser").value=C.ssh_user||""; $("#sshpass").value=C.ssh_pass||"";
 // open the credentials/ports panel when anything is prefilled, so it's visible
 if(Object.values(cl).some(Boolean) || Object.keys(BOOT.target_config||{}).length)
   { const d=$("#credpanel"); if(d) d.open=true; }
 if(BOOT.targets&&BOOT.targets.length){ $("#targets").value=BOOT.targets.join("\n");
   prefillTarget(BOOT.targets[0]); }        // prefill from the most-recent target
 // re-prefill whenever the first target line changes
 $("#targets").addEventListener("input",()=>{
   const first=$("#targets").value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean)[0];
   if(first) prefillTarget(first);});
 buildBattery(); buildVerdictKey(); applyPreset("original"); refresh(); loadRuns();
}

// Prefill the whole form for ONE target from its saved config (ports, cloud flag,
// egress source, posture, site, and that target's own creds — overriding the
// global defaults only where the target actually has a value).
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
 if(tc.mode){ MODE=(tc.mode==="whitebox")?"whitebox":"blackbox";
   $$("#modeseg button").forEach(b=>b.classList.toggle("on",b.dataset.v===MODE)); }
}

// Verdict key: every verdict label with its color + plain-language meaning.
// Each chip also acts as a verdict filter (click to toggle the table filter).
function buildVerdictKey(){
 const host=$("#vkey"); if(!host)return; host.innerHTML="";
 (BOOT.verdict_order||[]).forEach(v=>{
  const c=(BOOT.verdict_colors||{})[v]||"#8b90a6", g=(BOOT.verdict_gloss||{})[v]||"";
  const el=document.createElement("div"); el.className="vk"; el.dataset.v=v; el.title=v+" — "+g;
  el.innerHTML=`<i class=sw style="background:${c}"></i><b>${esc(v)}</b><span>${esc(g)}</span>`;
  el.addEventListener("click",()=>{
    const f=$("#fverdict");
    if(f.value===v){f.value="";}
    else{ if(![...f.options].some(o=>o.value===v)){const o=document.createElement("option");o.value=o.textContent=v;f.appendChild(o);} f.value=v; }
    renderRows();});
  host.appendChild(el);});
}
// reflect the active verdict filter on the key chips
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
   // full ATT&CK / CWE / scope mapping + remediation, shown on hover (title) so
   // every attack carries its complete detail, not just a lone technique id.
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
 $("#legend").innerHTML=ORDER.map(k=>
  `<span class=li><i class=sw style="background:${HEX[k]}"></i>${LABEL[k]} <b>${groups[k]||0}</b></span>`).join("");
 const got=groups.got||0;
 const ft=$("#findtally"); ft.textContent=got; ft.classList.toggle("zero",got===0);
 $("#t_det").textContent=groups.det||0; $("#t_blk").textContent=groups.blk||0;
}

function addRow(e){
 const row={n:++RESN, verdict:e.verdict||"", id:e.id||"", name:e.name||"", category:e.category||"",
  target:e.target||"", ports:e.ports||"", mitre:e.mitre||"", cwe:e.cwe||"", it:e.it||1, detail:e.detail||""};
 ROWS.push(row);
 COUNTS[e.verdict]=(COUNTS[e.verdict]||0)+1;
 syncFilterOptions(); renderRows(); refresh();
}
// keep the verdict / category / target filter dropdowns populated from live rows
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
function renderRows(){
 const rows=filteredRows(), tb=$("#resbody"); tb.innerHTML="";
 rows.forEach(r=>{const k=kindOf(r.verdict), c=HEX[k];
  const tr=document.createElement("tr");
  tr.dataset.id=r.id; tr.dataset.it=r.it; tr.dataset.target=r.target;
  tr.innerHTML=`<td class=mono>${r.n}</td>`
   +`<td class=vcell style="color:${c}"><span class=vbar style="background:${c}"></span>${esc(r.verdict)}</td>`
   +`<td>${esc(r.name)}</td><td class=dim>${esc(r.category)}</td>`
   +`<td class=mono>${esc(r.target)}</td><td class=mono>${esc(r.ports)}</td>`
   +`<td class=mono>${esc(r.mitre)}</td><td class=mono>${esc(r.cwe)}</td><td class=mono>${r.it}</td>`
   +`<td class=detail title="${esc(r.detail)}">${esc(r.detail)}</td>`;
  tr.addEventListener("click",()=>openRow(r));
  tb.appendChild(tr);});
 markVerdictKey();
 $("#rowcount").textContent=rows.length+(rows.length===ROWS.length?"":" / "+ROWS.length)+" rows";
 $$("#restable thead th").forEach(th=>{const a=th.querySelector(".ar"); if(a)a.remove();
  if(th.dataset.col===SORT.col){const s=document.createElement("span");s.className="ar";s.textContent=SORT.dir>0?"▲":"▼";th.appendChild(s);}});
}
// click a results row -> fetch that module's raw output and show it in the drawer
async function openRow(r){
 $("#dtitle").textContent=r.name+"  ["+r.verdict+"]";
 $("#dmeta").textContent=[r.target,r.category,r.ports,r.mitre&&("ATT&CK "+r.mitre),r.cwe&&("CWE "+r.cwe),"iter "+r.it].filter(Boolean).join("  •  ");
 $("#dbody").textContent="loading raw output…";
 $("#drawer").hidden=false;
 if(!RUNID){$("#dbody").textContent=r.detail||"(no run context)";return;}
 try{
  const u="api/run/"+RUNID+"/output?target="+encodeURIComponent(r.target)+"&id="+encodeURIComponent(r.id)+"&it="+encodeURIComponent(r.it);
  const j=await (await fetch(u)).json();
  $("#dbody").textContent=j.output!=null?j.output:("(no captured output — "+(j.error||"")+")\n\nverdict detail:\n"+r.detail);
 }catch(err){$("#dbody").textContent="(could not load output: "+err+")\n\nverdict detail:\n"+r.detail;}
}
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
 const L=$("#log"); L.appendChild(d); L.scrollTop=L.scrollHeight;
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
   if(j.error){$("#runmeta").textContent=j.error;$("#runmeta").style.color="var(--got)";return;}
   $("#runmeta").style.color="";
   COUNTS={};RESN=0;ROWS=[];RUNID=j.run_id;$("#resbody").innerHTML="";$("#rowcount").textContent="";$("#log").innerHTML="";$("#evidence").textContent="";$("#prog").style.width="0";refresh();
   $("#runbtn").disabled=true;$("#stopbtn").disabled=false;$("#stopbtn").dataset.id=j.run_id;
   stream(j.run_id);
  });
}
function stream(id){
 if(ES)ES.close(); ES=new EventSource("api/run/"+id+"/stream");
 ES.onmessage=ev=>{const e=JSON.parse(ev.data);
  if(e.type==="log")logLine(e.line);
  else if(e.type==="status")addRow(e);
  else if(e.type==="progress")$("#prog").style.width=(e.total?100*e.done/e.total:0)+"%";
  else if(e.type==="started")$("#runmeta").textContent=`running ${e.count} modules   ${e.mode}   ${e.iterations} iteration(s)   ${e.workers} workers`+(e.site_id?`   site ${e.site_id}`:"")+(e.active?"   active":"");
  else if(e.type==="target")logLine(`\n==== target ${e.index}/${e.total}: ${e.target} ====`);
  else if(e.type==="target_done")showEvidence(e.root);
  else if(e.type==="done")finish();
  else if(e.type==="error"){logLine("[error] "+e.error);finish();}
 };
 ES.onerror=()=>{};
}
function showEvidence(root){
 const b="evidence/"+root.replace(/^evidence\//,"")+"/";
 $("#evidence").innerHTML="evidence: "
  +`<a target=_blank href="${b}report.html">report</a> `
  +`<a target=_blank href="${b}summary.json">json</a> `
  +`<a target=_blank href="${b}report.txt">txt</a>`;
}
function finish(){
 $("#runbtn").disabled=false;$("#stopbtn").disabled=true;
 const got=Object.entries(COUNTS).filter(([v])=>kindOf(v)==="got").reduce((a,[,n])=>a+n,0);
 $("#runmeta").textContent=got?`run complete — ${got} got through`:"run complete";
 if(ES)ES.close(); loadRuns();
}
async function loadRuns(){
 const j=await (await fetch("api/runs")).json();
 $("#runs").innerHTML=(j.runs||[]).slice(0,12).map(r=>{
  const b="evidence/"+r.name+"/";
  const links=["report.html","summary.json"].filter(f=>r.files[f]).map(f=>`<a target=_blank href="${b}${f}">${f.split(".")[1]||f}</a>`).join(" ");
  return `<div class=runrow><b>${r.name}</b> ${links||'<span class=dim>no summary</span>'}</div>`;
 }).join("")||"—";
}

$("#modeseg").addEventListener("click",e=>{if(!e.target.dataset.v)return;
 MODE=e.target.dataset.v;$$("#modeseg button").forEach(b=>b.classList.toggle("on",b.dataset.v===MODE));});
$$("[data-preset]").forEach(b=>b.addEventListener("click",()=>applyPreset(b.dataset.preset)));
$("#runbtn").addEventListener("click",startRun);
$("#stopbtn").addEventListener("click",()=>fetch("api/run/"+$("#stopbtn").dataset.id+"/stop",{method:"POST"}));
// --- three-way tab switch (Results / Live log / History) ---
const TABS=[["#tabRes","#paneRes"],["#tabLog","#paneLog"],["#tabHist","#paneHist"]];
function showTab(tab){TABS.forEach(([t,p])=>{const on=(t===tab);
  $(t).classList.toggle("on",on);$(p).classList.toggle("hidden",!on);});
  if(tab==="#tabHist") loadHistory();}
TABS.forEach(([t])=>$(t).addEventListener("click",()=>showTab(t)));
// results: filter inputs re-render; header clicks sort; export scoped to this pane
["#fq","#fverdict","#fcat","#ftarget"].forEach(s=>$(s).addEventListener("input",renderRows));
$$("#restable thead th").forEach(th=>th.addEventListener("click",()=>{
 const c=th.dataset.col; if(!c)return;
 SORT.dir=(SORT.col===c)?-SORT.dir:1; SORT.col=c; renderRows();}));
$$("#paneRes .exp button").forEach(b=>b.addEventListener("click",()=>exportRows(b.dataset.exp)));
$("#dclose").addEventListener("click",()=>$("#drawer").hidden=true);
document.addEventListener("keydown",e=>{if(e.key==="Escape")$("#drawer").hidden=true;});

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
  const c=(BOOT.verdict_colors||{})[v]||"#8b90a6";
  return `<span class=hr><i style="background:${c}"></i>${esc(v)} <b>${o[v]}</b></span>`;}).join("")
  +` <span class=hr>runs <b>${stats.runs||0}</b></span>`;
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
 rows.forEach(r=>{const k=kindOf(r.verdict),col=HEX[k];
  const tr=document.createElement("tr");
  tr.innerHTML=`<td class=mono>${esc((r.ts||"").replace("T"," ").slice(5,19))}</td>`
   +`<td class=vcell style="color:${col}"><span class=vbar style="background:${col}"></span>${esc(r.verdict)}</td>`
   +`<td class=mono>${esc(r.target_ip)}</td><td>${esc(r.attack)}</td><td class=dim>${esc(r.category)}</td>`
   +`<td class=mono>${esc(r.mitre)}</td><td class=mono>${esc(r.cwe)}</td>`
   +`<td class=mono>${esc(r.site_id||"")}</td><td class=mono title="${esc(r.run_id)}">${esc((r.run_id||"").replace(/^run_/,""))}</td>`;
  tb.appendChild(tr);});
 $("#histcount").textContent=rows.length+" rows";
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
