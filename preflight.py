#!/usr/bin/env python3
"""
preflight.py — verify every attack module's external tools and privileges
are present BEFORE running the harness.

Cross-platform (Linux / macOS / Windows): tool presence is checked with
shutil.which, and an OS-appropriate install command is printed for anything
missing (apt/dnf/yum/pacman/zypper/apk, brew, winget/choco/scoop, or pip
for tools with no distro package). Auto-discovers modules the same way the
GUI does, so a newly dropped-in module is checked with no extra wiring.

Usage:
    python3 preflight.py                  # tool/privilege report (this host)
    python3 preflight.py --json           # machine-readable (for CI/tooling)
    python3 preflight.py --versions       # also probe tool versions (safe tools only)
    python3 preflight.py --target <IP>    # ALSO recon the target's ports first

Exit code: 0 if all discovered modules are ready, 1 otherwise (CI-friendly).

NOTE: --target actively contacts the target (a TCP connect to each module's
port), so it needs the same authorisation as running the exploits. The plain
(no --target) check only inspects THIS host and contacts nothing.
"""
import argparse
import json
import sys

import core
import loader


def main():
    ap = argparse.ArgumentParser(
        description="Preflight tool/privilege check for the control-validation harness.")
    ap.add_argument("--json", action="store_true",
                    help="emit the full preflight result as JSON")
    ap.add_argument("--versions", action="store_true",
                    help="also probe tool versions (best-effort; skips tools "
                         "that need root or have side effects)")
    ap.add_argument("--target", metavar="IP",
                    help="ALSO recon this target's ports (active — needs "
                         "authorisation, same as running the exploits)")
    args = ap.parse_args()

    modules = loader.discover()
    if not modules:
        print("[preflight] no modules discovered under modules/", file=sys.stderr)
        return 1

    pf = core.preflight(modules, want_versions=args.versions)
    rc = core.reachability(args.target, modules) if args.target else None

    if args.json:
        print(json.dumps({"preflight": pf, "recon": rc}, indent=2))
    else:
        print(core.format_preflight_report(pf))
        if rc is not None:
            print()
            print(core.format_reachability_report(rc))

    return 0 if all(r["ready"] for r in pf["modules"]) else 1


if __name__ == "__main__":
    sys.exit(main())
