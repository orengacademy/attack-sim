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
    # base set
    if args.original:
        sel = [m for m in modules if not m.META.get("added")]
    elif args.added:
        sel = [m for m in modules if m.META.get("added")]
    else:
        sel = list(modules)
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


def _print_summary(ev, args, no_color, elapsed):
    """Modern, detailed end-of-run summary from the evidence records: a verdict
    distribution with bars and a per-category table of every module's result."""
    DIM = "\033[2m"; BOLD = "\033[1m"; ACC = "\033[36m"
    recs = getattr(ev, "records", []) or []
    # aggregate per module across iterations (most-significant verdict wins)
    by_mod = {}
    for r in recs:
        mid = r.get("attack_id") or r.get("attack")
        d = by_mod.setdefault(mid, {"name": r.get("attack", mid), "cat": r.get("category", ""),
                                    "mitre": ", ".join(r.get("mitre", []) or []),
                                    "dir": r.get("direction", ""), "vs": []})
        d["vs"].append(r.get("baseline_result", "?"))
    for d in by_mod.values():
        d["v"] = next((v for v in _VERDICT_ORDER if v in d["vs"]), (d["vs"] or ["?"])[0])

    dist = {}
    for d in by_mod.values():
        dist[d["v"]] = dist.get(d["v"], 0) + 1
    n = len(by_mod)
    W = 72
    bar = "═" * W
    print()
    print(_c(f"╔{bar}╗", ACC, no_color))
    title = f" RESULTS — {args.target}   mode={args.mode}   {n} module(s) × {args.iterations} iter   {elapsed:.0f}s"
    print(_c("║", ACC, no_color) + _c(f"{title:<{W}}", BOLD, no_color) + _c("║", ACC, no_color))
    print(_c(f"╚{bar}╝", ACC, no_color))

    # distribution bars
    mx = max(dist.values()) if dist else 1
    for v in _VERDICT_ORDER:
        if v not in dist:
            continue
        col, icon = _VERDICT_STYLE.get(v, ("", "•"))
        blocks = int(round(20 * dist[v] / mx)) or 1
        meter = _c("█" * blocks, col, no_color) + _c("░" * (20 - blocks), DIM, no_color)
        print(f"  {_c(icon, col, no_color)} {_c(v, col, no_color):<22} {meter} {dist[v]}/{n}")

    # per-category table
    cats = {}
    for d in by_mod.values():
        cats.setdefault(d["cat"], []).append(d)
    for cat in sorted(cats):
        print("\n  " + _c(cat.upper(), ACC, no_color))
        for d in sorted(cats[cat], key=lambda x: (_VERDICT_ORDER.index(x["v"]) if x["v"] in _VERDICT_ORDER else 9, x["name"])):
            col, icon = _VERDICT_STYLE.get(d["v"], ("", "•"))
            mitre = _c(d["mitre"], DIM, no_color) if d["mitre"] else ""
            print(f"    {_c(icon, col, no_color)} {_c(d['v'], col, no_color):<22} "
                  f"{d['name']:<38} {mitre}")
    findings = dist.get("SUCCESS", 0) + dist.get("PASSED", 0)
    detected = dist.get("DETECTED", 0)
    print()
    print(_c(f"  → {findings} finding(s) got through"
             + (f", {detected} detected" if detected else "")
             + f"; {dist.get('BLOCKED', 0)} blocked.", BOLD, no_color))


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
    ap.add_argument("-t", "--target", help="target IP/host")
    ap.add_argument("-i", "--iterations", type=int, default=1)
    ap.add_argument("-w", "--workers", type=int, default=core.RECOMMENDED_WORKERS)
    ap.add_argument("--mode", choices=["blackbox", "whitebox"], default="blackbox")
    ap.add_argument("--no-recon", action="store_true", help="skip the reachability recon")
    ap.add_argument("--force", action="store_true",
                    help="run modules even if prerequisites are missing (default: skip)")
    ap.add_argument("--port", help='per-attack port overrides, e.g. "log4shell=8983,ssh_brute=2222"')
    sel = ap.add_mutually_exclusive_group()
    sel.add_argument("--only", help="comma list of module ids")
    sel.add_argument("--original", action="store_true", help="only the initial module set")
    sel.add_argument("--added", action="store_true", help="only the newly-added modules")
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
    ap.add_argument("--list", action="store_true", help="list discovered modules and exit")
    ap.add_argument("--confirm-roe", action="store_true",
                    help="confirm rules-of-engagement / written authorisation (required to run)")
    ap.add_argument("--evidence-dir", default="evidence")
    ap.add_argument("--no-color", action="store_true")
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

    if not args.target:
        ap.error("--target is required (or use --list)")
    if not args.confirm_roe:
        print("[!] refusing to run without --confirm-roe (rules-of-engagement / written "
              "authorisation). This tool runs real attacks against the target.", file=sys.stderr)
        return 2

    selected = _select(modules, args)
    if not selected:
        print("[!] no modules selected", file=sys.stderr)
        return 2

    runner = core.Runner(
        args.target, None,
        on_log=lambda m: print(_colorize(str(m), args.no_color)),
        on_status=lambda aid, name, it, b, v: None)  # per-attack lines already in on_log
    runner.concurrency = max(1, args.workers)
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
    # remember creds only when explicitly given this run (don't stamp the global
    # default onto every target).
    cred_fields = {}
    if args.domain is not None: cred_fields["domain"] = args.domain
    if args.dc_user is not None: cred_fields["dc_user"] = args.dc_user
    if args.dc_pass is not None: cred_fields["dc_pass"] = args.dc_pass
    core.remember_target(args.target, source=source or None, cloud=bool(cloud),
                         smb_port=(smb if cloud else None), rpc_port=(rpc if cloud else None),
                         **cred_fields)

    t0 = time.time()
    try:
        ev = core.Evidence(base=args.evidence_dir)
        root = runner.run(selected, max(1, args.iterations), ev,
                          skip_unready=not args.force, recon=not args.no_recon,
                          mode=args.mode)
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
    # full ATT&CK/CWE/CVE coverage report + evidence path
    try:
        with open(os.path.join(root, "report.txt")) as f:
            print("\n" + f.read())
    except Exception:
        pass
    print(_c(f"Evidence: {root}", "\033[36m", args.no_color))
    return 0


if __name__ == "__main__":
    sys.exit(main())
