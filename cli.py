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
    "SUCCESS": "\033[31m", "PASSED": "\033[31m",   # red — got through (finding)
    "BLOCKED": "\033[32m",                          # green — control worked
    "NO-SERVICE": "\033[34m",                       # blue — port closed, not a block
    "AUTH-FAILED": "\033[33m", "NO-RESULT": "\033[33m",  # amber — review
    "PREREQ-MISSING": "\033[90m",                   # grey — skipped
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
    if args.original:
        return [m for m in modules if not m.META.get("added")]
    if args.added:
        return [m for m in modules if m.META.get("added")]
    return list(modules)


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
    ap.add_argument("--list", action="store_true", help="list discovered modules and exit")
    ap.add_argument("--confirm-roe", action="store_true",
                    help="confirm rules-of-engagement / written authorisation (required to run)")
    ap.add_argument("--evidence-dir", default="evidence")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    modules = loader.discover()

    if args.list:
        print(f"{len(modules)} modules:")
        for m in sorted(modules, key=lambda x: x.META["id"]):
            meta = m.META
            tag = " [NEW]" if meta.get("added") else ""
            mitre = ", ".join(meta.get("mitre", []))
            print(f"  {meta['id']:<20} {meta['category']:<22} {mitre}{tag}")
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
