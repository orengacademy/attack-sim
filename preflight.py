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
    ap.add_argument("--version", action="version",
                    version=f"control-validation harness v{core.VERSION}")
    ap.add_argument("--json", action="store_true",
                    help="emit the full preflight result as JSON")
    ap.add_argument("--versions", action="store_true",
                    help="also probe tool versions (best-effort; skips tools "
                         "that need root or have side effects)")
    ap.add_argument("--target", metavar="IP[,IP...]",
                    help="ALSO recon these target(s)' ports — comma-separate for several "
                         "(e.g. the on-prem DC + the cloud DC). Active — needs "
                         "authorisation, same as running the exploits.")
    args = ap.parse_args()

    modules = loader.discover()
    if not modules:
        print("[preflight] no modules discovered under modules/", file=sys.stderr)
        return 1

    pf = core.preflight(modules, want_versions=args.versions)

    # recon each target (comma list). Apply each target's remembered cloud SMB/RPC/
    # SSH map first so recon probes the SAME ports the run will hit.
    targets = [t.strip() for t in (args.target or "").split(",") if t.strip()]
    recon = {}
    for tgt in targets:
        try:
            mem = core.recall_target(tgt)
            if mem.get("cloud"):
                from modules import _portpatch
                _portpatch.CUSTOM_PORT_TARGETS[tgt] = {
                    445: int(mem.get("smb_port") or 4445),
                    135: int(mem.get("rpc_port") or 1135),
                    22: int(mem.get("ssh_port") or 22)}  # match cli/gui default (was 2222)
            recon[tgt] = core.reachability(tgt, modules)
        except Exception as e:
            recon[tgt] = {"error": str(e)}

    if args.json:
        out = {"preflight": pf, "recon": (recon if len(targets) != 1 else recon.get(targets[0]))}
        print(json.dumps(out, indent=2))
    else:
        print(core.format_preflight_report(pf))
        for tgt in targets:
            print()
            rc = recon.get(tgt)
            if isinstance(rc, dict) and "error" in rc:
                print(f"[recon error for {tgt}: {rc['error']}]")
            elif rc is not None:
                if len(targets) > 1:
                    print(f"───── recon: {tgt} ─────")
                print(core.format_reachability_report(rc))
        # Boundary port policy (static/offline) — which modules reach the boundary
        # (allowed ports -> IPS/WAF test) vs are stopped at segmentation.
        pol = core.load_port_policy()
        allow, deny, egr = [], [], 0
        for m in modules:
            mp = core.module_policy(m.META, pol)
            if mp["outcome"] == "allowed":
                allow.append(m.META["name"])
            elif mp["outcome"] == "blocked":
                deny.append(m.META["name"])
            else:
                egr += 1
        print(f"\n===== PORT POLICY: {pol['name']} =====")
        print(f"  ALLOWED ports (reach boundary → IPS/WAF under test): {len(allow)}")
        print("    " + ", ".join(sorted(allow)))
        print(f"  DENIED/unlisted (expected SEGMENTATION block): {len(deny)}")
        print("    " + ", ".join(sorted(deny)))
        print(f"  egress/ICMP (policy n/a): {egr}")

    return 0 if all(r["ready"] for r in pf["modules"]) else 1


if __name__ == "__main__":
    sys.exit(main())
