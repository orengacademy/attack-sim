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

import core
import loader

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
    ap.add_argument("--cloud", action="store_true",
                    help="cloud target: SMB/RPC are on alternate ports (default 445->4445, "
                         "135->1135). Maps them for the AD modules AND the recon, so dcsync/"
                         "psexec/etc. and reachability hit the forwarded ports.")
    ap.add_argument("--smb-port", type=int, default=4445, help="cloud SMB alt port (--cloud)")
    ap.add_argument("--rpc-port", type=int, default=1135, help="cloud RPC alt port (--cloud)")
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
    if args.source:
        runner.ctx.source_ip = args.source
    if args.cloud:
        # register the target's NAT'd SMB/RPC ports so the impacket modules AND
        # recon use the forwarded alternates (same map as modules/_portpatch.py).
        try:
            from modules import _portpatch
            _portpatch.CUSTOM_PORT_TARGETS[args.target] = {445: args.smb_port, 135: args.rpc_port}
            print(f"[cloud] {args.target}: SMB 445->{args.smb_port}, RPC 135->{args.rpc_port}")
        except Exception as e:
            print(f"[!] could not enable cloud ports: {e}", file=sys.stderr)

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

    # print the report tail (coverage) and where the evidence is
    try:
        with open(os.path.join(root, "report.txt")) as f:
            print("\n" + f.read())
    except Exception:
        pass
    print(f"Evidence: {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
