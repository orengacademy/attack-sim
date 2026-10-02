#!/usr/bin/env python3
"""
cli.py — headless runner (no GUI / no $DISPLAY needed). For servers & SSH.

Examples:
  python3 cli.py --list
  python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe
  python3 cli.py --target 10.0.0.5 --only ssh_brute,ftp_anonymous --workers 4 --confirm-roe
  python3 cli.py --target 10.0.0.5 --original --iterations 3 --confirm-roe
  python3 cli.py --target 10.0.0.5 --port log4shell=8983,ssh_brute=2222 --confirm-roe

Everything the GUI does, from the command line. Results are colour-coded with the
purple-team convention: RED = attack PASSED (got through — finding), GREEN =
BLOCKED (control worked), BLUE = NO-SERVICE (port closed, not a block).
"""
import argparse
import os
import sys
import time

import core
import loader

# verdict -> (ANSI colour, icon) for the modern summary
_VERDICT_STYLE = {
    "SUCCESS":        ("\033[31m", "●"),   # red    — got through undetected (finding)
    "PASSED":         ("\033[31m", "●"),
    "DETECTED":       ("\033[38;5;208m", "◐"),  # orange — passed but SOC alerted
    "BLOCKED":        ("\033[32m", "■"),   # green  — control worked
    "NO-SERVICE":     ("\033[34m", "○"),   # blue   — port closed, not a block
    "AUTH-FAILED":    ("\033[33m", "▲"),   # amber  — bad creds
    "NO-RESULT":      ("\033[33m", "?"),   # amber  — review
    "SKIPPED":        ("\033[90m", "–"),   # grey   — did nothing
    "PREREQ-MISSING": ("\033[90m", "–"),
}
_VERDICT_ORDER = ["SUCCESS", "PASSED", "DETECTED", "BLOCKED", "NO-SERVICE",
                  "AUTH-FAILED", "NO-RESULT", "SKIPPED", "PREREQ-MISSING"]

_ANSI = {
    "SUCCESS": "\033[31m", "PASSED": "\033[31m",   # red — got through undetected (finding)
    "DETECTED": "\033[38;5;208m",                   # orange — passed but SOC alerted
    "BLOCKED": "\033[32m",                          # green — control worked
    "NO-SERVICE": "\033[34m",                       # blue — port closed, not a block
    "AUTH-FAILED": "\033[33m", "NO-RESULT": "\033[33m",  # amber — review
    "SKIP": "\033[90m", "SKIPPED": "\033[90m", "PREREQ-MISSING": "\033[90m",  # grey — skipped
}
_RESET = "\033[0m"


def _colorize(text, no_color):
    if no_color or not sys.stdout.isatty():
        return text
    for st, c in _ANSI.items():
        tok = f"[{st}]"
        if tok in text:
            return text.replace(tok, f"{c}{tok}{_RESET}")
    return text


def _select(modules, args):
    if args.only:
        want = {x.strip() for x in args.only.split(",") if x.strip()}
        sel = [m for m in modules if m.META["id"] in want]
        missing = want - {m.META["id"] for m in sel}
        if missing:
            print(f"[!] unknown module id(s): {', '.join(sorted(missing))}", file=sys.stderr)
        return sel
    # base set. DEFAULT = the original 11-module baseline (same as the GUI's
    # default tick) — a bare `cli.py --target X` runs a sensible, fast,
    # self-contained set rather than all 48. Use --all for everything.
    if getattr(args, "all", False):
        sel = list(modules)
    elif args.added:
        sel = [m for m in modules if m.META.get("added")]
    else:  # --original or nothing given
        sel = [m for m in modules if not m.META.get("added")]
    # scope filters (compose with the base set)
    tt = "attack_sim" if args.attack_sim else args.test_type
    if tt:
        sel = [m for m in sel if m.META.get("test_type") == tt]
    if args.family:
        fams = {f.strip().upper() for f in args.family.split(",") if f.strip()}
        sel = [m for m in sel if m.META.get("family", "").upper() in fams]
    if args.direction:
        d = args.direction.lower()
        # a module tagged "both" always matches; otherwise exact direction match.
        sel = [m for m in sel
               if m.META.get("direction", "a2b").lower() in (d, "both")]
    return sel


def _c(s, color, no_color):
    return s if no_color or not sys.stdout.isatty() else f"{color}{s}{_RESET}"


DIM = "\033[2m"; BOLD = "\033[1m"; ACC = "\033[36m"

# one-line human gloss per verdict, for the table's DETAIL column
_VERDICT_GLOSS = {
    "SUCCESS":        "got through — undetected (finding)",
    "PASSED":         "got through — undetected (finding)",
    "DETECTED":       "got through but SOC alerted",
    "BLOCKED":        "control worked — attack stopped",
    "NO-SERVICE":     "port closed — service not present",
    "AUTH-FAILED":    "bad credentials — fix creds",
    "NO-RESULT":      "inconclusive — review raw log",
    "SKIPPED":        "did nothing — n/a or unconfigured",
    "PREREQ-MISSING": "prerequisite missing — not run",
}


def _cell(text, w, color, no_color):
    """A fixed-width table cell: truncate, pad, then colour the whole cell (ANSI
    codes don't count toward width because padding happens first)."""
    text = "" if text is None else str(text)
    if len(text) > w:
        text = text[:w - 1] + "…"
    text = f"{text:<{w}}"
    return _c(text, color, no_color) if color else text


def _print_summary(ev, args, no_color, elapsed):
    """Modern end-of-run summary from the evidence records: a verdict-distribution
    strip plus one aligned, colour-coded TABLE of every module's result."""
    recs = getattr(ev, "records", []) or []
    # aggregate per module across iterations (most-significant verdict wins)
    by_mod = {}
    for r in recs:
        mid = r.get("attack_id") or r.get("attack")
        d = by_mod.setdefault(mid, {"name": r.get("attack", mid), "cat": r.get("category", ""),
                                    "mitre": ", ".join(r.get("mitre", []) or []),
                                    "dir": r.get("direction", ""), "vs": [],
                                    "verdicts": {}, "outputs": {}})
        br = r.get("baseline_result", "?")
        d["vs"].append(br)
        d["verdicts"][br] = r.get("verdict", "")
        d["outputs"][br] = r.get("output", "") or ""
        if r.get("duration_s") is not None:
            d["dur"] = max(d.get("dur", 0.0), r["duration_s"])
    for d in by_mod.values():
        d["v"] = next((v for v in _VERDICT_ORDER if v in d["vs"]), (d["vs"] or ["?"])[0])

    dist = {}
    for d in by_mod.values():
        dist[d["v"]] = dist.get(d["v"], 0) + 1
    n = len(by_mod)

    # ---- header strip --------------------------------------------------
    import datetime as _dt
    site = (getattr(ev, "meta", {}) or {}).get("site_id") or getattr(args, "site_id", None)
    W = 78

    def _hline(text):
        print(_c("┃", ACC, no_color) + _c(f"{text:<{W}}", BOLD, no_color)
              + _c("┃", ACC, no_color))
    print()
    print(_c("┏" + "━" * W + "┓", ACC, no_color))
    _hline(f"  CONTROL VALIDATION — RESULTS" + (f"   ·   SITE {site}" if site else ""))
    _hline(f"  {args.target}   ·   {args.mode}   ·   {n} module(s) × {args.iterations} iter"
           f"   ·   {elapsed:.0f}s")
    _hline(f"  {_dt.datetime.now():%Y-%m-%d %H:%M:%S}"
           + ("   ·   DEBUG" if getattr(args, "debug", False) else ""))
    print(_c("┗" + "━" * W + "┛", ACC, no_color))

    # ---- distribution strip -------------------------------------------
    mx = max(dist.values()) if dist else 1
    for v in _VERDICT_ORDER:
        if v not in dist:
            continue
        col, icon = _VERDICT_STYLE.get(v, ("", "•"))
        blocks = int(round(18 * dist[v] / mx)) or 1
        meter = _c("█" * blocks, col, no_color) + _c("░" * (18 - blocks), DIM, no_color)
        print(f"  {_c(icon, col, no_color)} {_c(v, col, no_color):<22} {meter} "
              f"{dist[v]}/{n}")

    # ---- the table -----------------------------------------------------
    debug = getattr(args, "debug", False)
    NUM, VER, MOD, CAT, DET = 3, 13, 36, 20, 34
    cols = [("#", NUM), ("VERDICT", VER), ("MODULE", MOD), ("CATEGORY", CAT), ("DETAIL", DET)]
    if debug:
        cols.append(("TIME", 7))   # per-module wall-clock (debug only)
    inner = [w for _, w in cols]

    def rule(left, mid, right):
        return _c(left + mid.join("─" * (w + 2) for w in inner) + right, DIM, no_color)

    def row(cells, colors=None):
        colors = colors or [None] * len(cells)
        parts = [_cell(c, inner[i], colors[i], no_color) for i, c in enumerate(cells)]
        sep = _c("│", DIM, no_color)
        return sep + " " + (" " + sep + " ").join(parts) + " " + sep

    print()
    print(rule("┌", "┬", "┐"))
    print(row([h for h, _ in cols], [BOLD] * len(cols)))
    print(rule("├", "┼", "┤"))

    rows = sorted(by_mod.values(),
                  key=lambda x: (x["cat"],
                                 _VERDICT_ORDER.index(x["v"]) if x["v"] in _VERDICT_ORDER else 9,
                                 x["name"]))
    prev_cat = None
    i = 0
    for d in rows:
        i += 1
        col, icon = _VERDICT_STYLE.get(d["v"], ("", "•"))
        cat = d["cat"] if d["cat"] != prev_cat else ""
        prev_cat = d["cat"]
        detail = _VERDICT_GLOSS.get(d["v"], "")
        # sharpen the BLOCKED detail so it says WHERE/WHY the block came from.
        if d["v"] == "BLOCKED":
            vtext = d["verdicts"].get("BLOCKED", "") or ""
            otext = d["outputs"].get("BLOCKED", "") or ""
            if "REJECTION RESPONSE" in vtext:
                detail = "rejection block (in-path IPS/WAF or host)"
            elif "BLOCKED-RATELIMIT" in otext:
                detail = "rate-limited/shaped (boundary policed the flood)"
        cells = [str(i), f"{icon} {d['v']}", d["name"], cat, detail]
        colors = [DIM, col, None, ACC, DIM]
        if debug:
            cells.append(f"{d.get('dur', 0.0):.1f}s")
            colors.append(DIM)
        print(row(cells, colors))
    print(rule("└", "┴", "┘"))

    findings = dist.get("SUCCESS", 0) + dist.get("PASSED", 0)
    detected = dist.get("DETECTED", 0)
    blocked = dist.get("BLOCKED", 0)
    print()
    print(_c(f"  → {findings} finding(s) got through"
             + (f", {detected} detected" if detected else "")
             + f"; {blocked} blocked.", BOLD, no_color))


def _parse_ports(spec):
    out = {}
    for part in (spec or "").replace(";", ",").split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            if v.strip().isdigit():
                out[k.strip()] = int(v.strip())
    return out


def main():
    ap = argparse.ArgumentParser(description="Headless control-validation harness runner.")
    ap.add_argument("-t", "--target", default="127.0.0.1",
                    help="target IP/host (default: 127.0.0.1 — the local lab)")
    ap.add_argument("-i", "--iterations", type=int, default=1)
    ap.add_argument("-w", "--workers", type=int, default=core.RECOMMENDED_WORKERS)
    ap.add_argument("--mode", choices=["blackbox", "whitebox"], default="blackbox")
    ap.add_argument("-s", "--site-id", "--site", dest="site_id", default=None,
                    help="engagement/site tag recorded in the evidence + headers "
                         "(remembered per target; or set HARNESS_SITE_ID)")
    ap.add_argument("--debug", action="store_true",
                    help="verbose: ask tools for their own debug trace (curl -v / "
                         "ldapsearch -v / hydra -d / impacket -debug), stream each "
                         "module's full raw output live, and show per-module timing")
    ap.add_argument("--no-recon", action="store_true", help="skip the reachability recon")
    ap.add_argument("--force", action="store_true",
                    help="run modules even if prerequisites are missing (default: skip)")
    ap.add_argument("--port", help='per-attack port overrides, e.g. "log4shell=8983,ssh_brute=2222"')
    sel = ap.add_mutually_exclusive_group()
    sel.add_argument("--only", help="comma list of module ids")
    sel.add_argument("--original", action="store_true",
                     help="only the initial 11-module baseline set (THIS IS THE DEFAULT)")
    sel.add_argument("--added", action="store_true", help="only the newly-added modules")
    sel.add_argument("--all", action="store_true", help="run ALL discovered modules (not just the baseline)")
    ap.add_argument("--test-type", choices=["attack_sim", "pentest", "va", "dos"],
                    help="filter to a test type (attack_sim = the USS boundary scope)")
    ap.add_argument("--attack-sim", action="store_true",
                    help="shortcut for --test-type attack_sim (USS scope only)")
    ap.add_argument("--family", help="filter attack-sim families, e.g. A,B,D")
    ap.add_argument("--direction", choices=["a2b", "b2a", "both"],
                    help="filter by test direction: a2b = SDWAN/site->DC (northbound), "
                         "b2a = DC->SDWAN/out (reverse/server-initiated)")
    ap.add_argument("--active", action="store_true",
                    help="ALLOW active establishment — live modules may build real "
                         "tunnels / SOCKS pivots / DNS tunnels / exfil to YOUR configured "
                         "infra (default: non-destructive indicator mode only). Use only "
                         "inside the authorised window.")
    ap.add_argument("--source", help="source IP to bind egress sockets to (e.g. a DC "
                    "foothold interface / VRF); default = OS route")
    ap.add_argument("--cloud", dest="cloud", action="store_const", const=True, default=None,
                    help="cloud target: SMB/RPC are on alternate ports (default 445->4445, "
                         "135->1135). Maps them for the AD modules AND the recon. If omitted, "
                         "the last --cloud/--source used for this target is recalled.")
    ap.add_argument("--no-cloud", dest="cloud", action="store_const", const=False,
                    help="force cloud mode OFF (ignore any remembered --cloud for this target)")
    ap.add_argument("--smb-port", type=int, default=None, help="cloud SMB alt port (default 4445)")
    ap.add_argument("--rpc-port", type=int, default=None, help="cloud RPC alt port (default 1135)")
    # per-target credentials (override HARNESS_DC_*/credentials.env for THIS target
    # and are remembered for it — so a Linux target and a Windows DC can differ)
    ap.add_argument("--domain", help="AD domain for this target (e.g. lab.local)")
    ap.add_argument("--dc-user", help="username for this target (e.g. Administrator)")
    ap.add_argument("--dc-pass", help="password for this target (remembered per target, file is 0600)")
    # SSH creds are SEPARATE from the DC creds — a dual-role target is both an
    # SSH host and a DC front, and one identity can't serve both. ssh_brute uses
    # these; if unset it falls back to --dc-user/--dc-pass.
    ap.add_argument("--ssh-user", help="SSH username for this target (ssh_brute; falls back to --dc-user)")
    ap.add_argument("--ssh-pass", help="SSH password for this target (remembered per target, 0600)")
    ap.add_argument("--list", action="store_true", help="list discovered modules and exit")
    ap.add_argument("--confirm-roe", action="store_true",
                    help="confirm rules-of-engagement / written authorisation (required to run)")
    ap.add_argument("--evidence-dir", default="evidence")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--full-report", action="store_true",
                    help="also print the full ATT&CK/CWE/CVE report.txt to the console "
                         "(it is always written to the evidence dir regardless)")
    args = ap.parse_args()

    modules = loader.discover()

    if args.list:
        print(f"{len(modules)} modules:")
        for m in sorted(modules, key=lambda x: (x.META.get("test_type", ""),
                                                x.META.get("family", ""), x.META["id"])):
            meta = m.META
            tags = []
            if meta.get("added"):
                tags.append("NEW")
            if meta.get("active"):
                tags.append("ACTIVE")
            tag = (" [" + ",".join(tags) + "]") if tags else ""
            scope = meta.get("test_type", "?")
            fam = f"/{meta['family']}" if meta.get("family") else ""
            dirn = meta.get("direction", "a2b")
            mitre = ", ".join(meta.get("mitre", []))
            print(f"  {meta['id']:<26} {scope+fam:<14} {dirn:<5} {mitre}{tag}")
        print("\nattack_sim = the USS boundary scope (families A-G). Filter a run with "
              "--attack-sim / --family A,B,D / --direction a2b|b2a.\n"
              "[ACTIVE] modules need --active (+ config.json infra) to establish for real; "
              "otherwise they run as non-destructive indicators.")
        return 0

    target_defaulted = not any(a in ("-t", "--target") for a in sys.argv)
    if target_defaulted:
        print(f"[default] no --target given → using {args.target} (the local lab). "
              "Pass --target <ip> for a remote target.")
    if not args.confirm_roe:
        print("[!] refusing to run without --confirm-roe (rules-of-engagement / written "
              "authorisation). This tool runs REAL attacks against the target.\n"
              f"    Re-run:  python3 cli.py --target {args.target} --confirm-roe",
              file=sys.stderr)
        return 2

    selected = _select(modules, args)
    if not selected:
        print("[!] no modules selected", file=sys.stderr)
        return 2

    # Clean live rendering: the engine's own per-module log lines interleave
    # under concurrency; suppress those on the console (they stay in the
    # evidence run.log) and re-render each result as a tidy numbered line via
    # on_status. The banner / preflight / recon / health setup output is kept.
    _cats = {m.META.get("category", "") for m in selected}
    _total = len(selected) * max(1, args.iterations)
    _prog = {"n": 0}

    def _on_log(m):
        s = str(m)
        if args.debug:                      # debug: keep the full engine stream
            print(_colorize(s, args.no_color))
            return
        st = s.strip()
        if st.lower().startswith(("target:", "baseline:")):
            return  # per-module verdict line — re-rendered by on_status
        for c in _cats:                     # "  [Category] Name" now-running line
            if c and st.startswith(f"[{c}]"):
                return
        print(_colorize(s, args.no_color))

    def _on_output(aid, name, it, raw):
        # debug: stream each module's FULL raw output live (command + stdout +
        # stderr + the tool's own -v/-debug trace), like the GUI's output panel.
        if not args.debug:
            return
        print(_c(f"\n──── {name} — raw output ────", DIM, args.no_color))
        print(str(raw).rstrip())

    def _on_status(aid, name, it, b, v):
        _prog["n"] += 1
        col, icon = _VERDICT_STYLE.get(b, ("", "•"))
        idx = _c(f"[{_prog['n']:>2}/{_total}]", DIM, args.no_color)
        # pad the PLAIN label to a fixed width, THEN colour it, so ANSI codes
        # don't throw the column alignment off.
        verd = _c(f"{icon} {b:<13}", col, args.no_color)
        print(f"  {idx} {verd} {name}")

    runner = core.Runner(
        args.target, None,
        on_log=_on_log,
        on_output=_on_output,
        on_status=_on_status)
    runner.concurrency = max(1, args.workers)
    runner.ctx.debug = bool(args.debug)
    overrides = _parse_ports(args.port)
    if overrides:
        runner.ctx.port_overrides = overrides
    runner.ctx.allow_active = bool(args.active)

    # Per-target memory: recall the last source/cloud options for this target when
    # the flag was omitted, then persist whatever we end up using.
    mem = core.recall_target(args.target)
    source = args.source if args.source is not None else mem.get("source")
    cloud = args.cloud if args.cloud is not None else bool(mem.get("cloud"))
    smb = args.smb_port or (mem.get("smb_port") if cloud else None) or 4445
    rpc = args.rpc_port or (mem.get("rpc_port") if cloud else None) or 1135
    if source:
        runner.ctx.source_ip = source
        if args.source is None:
            print(f"[recall] source {source} (remembered for {args.target})")
    if cloud:
        try:
            from modules import _portpatch
            _portpatch.CUSTOM_PORT_TARGETS[args.target] = {445: int(smb), 135: int(rpc)}
            tag = "" if args.cloud is not None else " (recalled)"
            print(f"[cloud{tag}] {args.target}: SMB 445->{smb}, RPC 135->{rpc}")
        except Exception as e:
            print(f"[!] could not enable cloud ports: {e}", file=sys.stderr)

    # Per-target CREDENTIALS. One global HARNESS_DC_* / credentials.env can't serve
    # both a Linux SSH lab (labadmin) and a Windows DC (Administrator) — so a flag
    # (or the value remembered for THIS target) overrides them per target.
    dom = args.domain or mem.get("domain")
    usr = args.dc_user or mem.get("dc_user")
    pw = args.dc_pass if args.dc_pass is not None else mem.get("dc_pass")
    if dom:
        runner.ctx.creds["domain"] = dom
    if usr:
        runner.ctx.creds["dc_user"] = usr
    if pw is not None:
        runner.ctx.creds["dc_pass"] = pw
    if (dom or usr or pw is not None) and not (args.domain or args.dc_user or args.dc_pass is not None):
        print(f"[recall] creds for {args.target}: {runner.ctx.creds.get('domain')}/"
              f"{runner.ctx.creds.get('dc_user')} (remembered)")
    # SSH creds, separate from the DC creds (dual-role target: SSH host + DC).
    ssh_u = args.ssh_user or mem.get("ssh_user")
    ssh_p = args.ssh_pass if args.ssh_pass is not None else mem.get("ssh_pass")
    if ssh_u:
        runner.ctx.creds["ssh_user"] = ssh_u
    if ssh_p is not None:
        runner.ctx.creds["ssh_pass"] = ssh_p
    # Site ID: flag > remembered > env. Recorded in evidence + echoed in headers.
    site_id = args.site_id or mem.get("site_id") or ""
    if site_id and not args.site_id:
        print(f"[recall] site {site_id} (remembered for {args.target})")
    # remember creds/site only when explicitly given this run (don't stamp the
    # global default onto every target).
    cred_fields = {}
    if args.domain is not None: cred_fields["domain"] = args.domain
    if args.dc_user is not None: cred_fields["dc_user"] = args.dc_user
    if args.dc_pass is not None: cred_fields["dc_pass"] = args.dc_pass
    if args.ssh_user is not None: cred_fields["ssh_user"] = args.ssh_user
    if args.ssh_pass is not None: cred_fields["ssh_pass"] = args.ssh_pass
    if args.site_id is not None: cred_fields["site_id"] = args.site_id
    core.remember_target(args.target, source=source or None, cloud=bool(cloud),
                         smb_port=(smb if cloud else None), rpc_port=(rpc if cloud else None),
                         **cred_fields)

    t0 = time.time()
    try:
        ev = core.Evidence(base=args.evidence_dir)
        root = runner.run(selected, max(1, args.iterations), ev,
                          skip_unready=not args.force, recon=not args.no_recon,
                          mode=args.mode, site_id=site_id or None)
    except ValueError as e:               # invalid target / allowlist refusal
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130

    # modern per-module summary (from the evidence records)
    try:
        _print_summary(ev, args, args.no_color, time.time() - t0)
    except Exception as e:
        print(f"[!] summary error (non-fatal): {e}", file=sys.stderr)
    # full ATT&CK/CWE/CVE coverage report: written to evidence always; echoed to
    # the console only with --full-report (keeps the default output clean).
    report_path = os.path.join(root, "report.txt")
    if args.full_report:
        try:
            with open(report_path) as f:
                print("\n" + f.read())
        except Exception:
            pass
    else:
        print(_c(f"\n  Full ATT&CK/CWE/CVE report:  {report_path}"
                 "   (add --full-report to print it here)", DIM, args.no_color))
    print(_c(f"  Evidence:                    {root}", ACC, args.no_color))
    return 0


if __name__ == "__main__":
    sys.exit(main())
