#!/usr/bin/env python3
"""fleet.py — run the control-validation harness across N vulnerable servers.

MyGovNet has many vuln servers across zones (DO/KVDC/IPDC/PDSA/Global/PCN/SDWAN).
This drives the SAME engine (core.Runner) over a fleet defined in fleet.json: a
zone-to-zone matrix, both directions, with per-target NAT'd SMB/RPC ports and
per-source egress binding. One target is still cli.py; this is the N-target front.

  python3 fleet.py --list-targets                       # show the fleet
  python3 fleet.py --dry-run                             # preview the job matrix
  python3 fleet.py --attack-sim --confirm-roe            # run the whole matrix (USS scope)
  python3 fleet.py --to kvdc,cloud --direction a2b --confirm-roe
  python3 fleet.py --only dcsync,psexec --from sdwan --confirm-roe

Each job = (source foothold in a `from` zone)  ->  (target in a `to` zone) in a
direction. Evidence lands in evidence/fleet_<ts>/<source_id>__<target_id>/.
"""
import argparse
import json
import os
import sys
import types
from datetime import datetime

import core
import loader
from cli import _select, _colorize


def load_fleet(path):
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data.get("targets"), list) or not data["targets"]:
        raise ValueError(f"{path}: no 'targets' defined")
    return data


def _by_zone(items):
    out = {}
    for it in items:
        out.setdefault(it.get("zone", ""), []).append(it)
    return out


def build_jobs(fleet, args):
    """Expand the fleet into a flat list of {source, target, direction} jobs."""
    targets_by_zone = _by_zone(fleet.get("targets", []))
    sources_by_zone = _by_zone(fleet.get("sources", []))
    runs = fleet.get("runs", [])
    jobs = []

    if runs:
        for r in runs:
            fz = r.get("from", "")
            tos = r.get("to", [])
            tos = tos if isinstance(tos, list) else [tos]
            direction = r.get("direction")
            # a source foothold per from-zone; if none configured, use default route
            srcs = sources_by_zone.get(fz) or [{"id": fz or "local", "ip": None, "zone": fz}]
            for s in srcs:
                for tz in tos:
                    for t in targets_by_zone.get(tz, []):
                        jobs.append({"source": s, "target": t, "direction": direction})
    else:
        # no matrix -> every target once, from the default route, all directions
        for t in fleet.get("targets", []):
            jobs.append({"source": {"id": "local", "ip": None}, "target": t, "direction": None})

    # ---- filters ----
    if args.to:
        zs = {z.strip() for z in args.to.split(",") if z.strip()}
        jobs = [j for j in jobs if j["target"].get("zone") in zs]
    if getattr(args, "from_zone", None):
        zs = {z.strip() for z in args.from_zone.split(",") if z.strip()}
        jobs = [j for j in jobs if j["source"].get("zone") in zs]
    # "both" means ALL directions (like cli._select), so only filter jobs for a
    # specific a2b/b2a; filtering on "both" would drop every directional job.
    if args.direction and args.direction != "both":
        jobs = [j for j in jobs
                if j["direction"] is None or j["direction"] == args.direction]
    return jobs


def _sel_args(args, direction):
    """A Namespace shaped for cli._select, with the job's direction applied."""
    return types.SimpleNamespace(
        only=args.only, original=args.original, added=args.added,
        attack_sim=args.attack_sim, test_type=args.test_type,
        family=args.family, direction=direction or args.direction)


def _verdict_counts(records):
    c = {}
    for r in records:
        v = r.get("baseline_result", "?")
        c[v] = c.get(v, 0) + 1
    return c


def main():
    ap = argparse.ArgumentParser(description="Run the harness across a fleet of N vuln servers.")
    ap.add_argument("--fleet", default="fleet.json", help="fleet definition (default: fleet.json)")
    ap.add_argument("-i", "--iterations", type=int, default=1)
    ap.add_argument("-w", "--workers", type=int, default=core.RECOMMENDED_WORKERS)
    ap.add_argument("--mode", choices=["blackbox", "whitebox", "auto"], default="auto",
                    help="posture for every job (default 'auto' = each target's DESIGNATED "
                         "posture from memory; blackbox/whitebox forces one for the whole fleet)")
    ap.add_argument("--no-recon", action="store_true")
    ap.add_argument("--force", action="store_true", help="run modules even if prereqs missing")
    # module selection (same semantics as cli.py)
    sel = ap.add_mutually_exclusive_group()
    sel.add_argument("--only", help="comma list of module ids")
    sel.add_argument("--original", action="store_true")
    sel.add_argument("--added", action="store_true")
    ap.add_argument("--test-type", choices=["attack_sim", "pentest", "va", "dos"])
    ap.add_argument("--attack-sim", action="store_true", help="USS boundary scope only")
    ap.add_argument("--family", help="attack-sim families, e.g. A,B,D")
    # fleet scoping
    ap.add_argument("--to", help="only target these zones (comma list), e.g. kvdc,cloud")
    ap.add_argument("--from", dest="from_zone", help="only these source zones (comma list)")
    ap.add_argument("--direction", choices=["a2b", "b2a", "both"],
                    help="only jobs/modules in this direction")
    ap.add_argument("--active", action="store_true", help="allow active establishment")
    ap.add_argument("--list-targets", action="store_true", help="print the fleet and exit")
    ap.add_argument("--dry-run", action="store_true", help="print the job matrix and exit")
    ap.add_argument("--confirm-roe", action="store_true",
                    help="required to run (RoE) — unless a DURABLE opt-in is on file "
                         "(.roe_accepted via `cli.py --accept-roe`, or HARNESS_CONFIRM_ROE=1)")
    ap.add_argument("--evidence-dir", default="evidence")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    core.enforce_latest_version()   # refuse to run an outdated copy (see core.py)

    try:
        fleet = load_fleet(args.fleet)
    except FileNotFoundError:
        print(f"[!] {args.fleet} not found — copy fleet.json.example to fleet.json and edit it.",
              file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    if args.list_targets:
        print(f"{len(fleet.get('targets', []))} targets:")
        for t in fleet.get("targets", []):
            cp = f"  cloud_ports={t['cloud_ports']}" if t.get("cloud_ports") else ""
            print(f"  {t.get('id',''):<12} {t.get('ip',''):<18} zone={t.get('zone','')}{cp}")
        srcs = fleet.get("sources", [])
        if srcs:
            print(f"\n{len(srcs)} sources:")
            for s in srcs:
                print(f"  {s.get('id',''):<16} {s.get('ip',''):<18} zone={s.get('zone','')}")
        return 0

    modules = loader.discover()
    jobs = build_jobs(fleet, args)
    if not jobs:
        print("[!] no jobs after filtering — check --to/--from/--direction and the fleet.", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"Job matrix ({len(jobs)} jobs):")
        for j in jobs:
            s, t = j["source"], j["target"]
            sel = _select(modules, _sel_args(args, j["direction"]))
            print(f"  {s.get('id','local'):<16} ({s.get('ip') or 'default-route'}) "
                  f"-> {t['id']:<12} {t['ip']:<18} [{j['direction'] or 'all'}]  "
                  f"{len(sel)} module(s)")
        return 0

    # Honor the SAME durable opt-in as cli/gui/web (core.roe_accepted(): the
    # git-ignored .roe_accepted file or HARNESS_CONFIRM_ROE=1) so the ROE gate is
    # consistent across every front-end — fleet used to demand --confirm-roe even
    # with the opt-in on file. Still an explicit, operator-chosen opt-in (never a
    # silent default-on): with neither, it refuses.
    if not (args.confirm_roe or core.roe_accepted()):
        print("[!] refusing to run without rules-of-engagement confirmation (this runs real "
              "attacks against every target). Satisfy it once with:\n"
              "    python3 cli.py --accept-roe       # durable opt-in (writes .roe_accepted)\n"
              "  or set HARNESS_CONFIRM_ROE=1 in your env, or pass --confirm-roe per run.",
              file=sys.stderr)
        return 2

    ts = datetime.now().strftime("%d-%m-%H-%M")
    # Claim the fleet dir atomically (same minute-collision race as single runs —
    # two fleet runs in one minute would otherwise share fleet_<ts> and interleave).
    base = core._claim_run_dir(args.evidence_dir, f"fleet_{ts}")
    print(f"=== FLEET RUN {ts} — {len(jobs)} job(s) -> {base} ===")
    fleet_summary = {"started": datetime.now().isoformat(), "mode": args.mode, "jobs": []}

    for n, j in enumerate(jobs, 1):
        s, t = j["source"], j["target"]
        # posture is PER TARGET: fleet.json 'mode' on the target wins, else the
        # fleet-wide --mode (default 'auto' = each target's designated posture).
        job_mode = core.resolve_posture(t["ip"], t.get("mode") or args.mode)
        selected = _select(modules, _sel_args(args, j["direction"]))
        hdr = (f"\n[{n}/{len(jobs)}] {s.get('id','local')} ({s.get('ip') or 'default'}) "
               f"-> {t['id']} {t['ip']} zone={t.get('zone','')} dir={j['direction'] or 'all'} "
               f"posture={job_mode} ({len(selected)} modules)")
        print(_colorize(hdr, args.no_color))
        if not selected:
            print("  (no modules selected for this job — skipped)")
            continue

        # per-target NAT'd SMB/RPC ports -> the impacket modules + recon use them
        if t.get("cloud_ports"):
            try:
                from modules import _portpatch
                _portpatch.CUSTOM_PORT_TARGETS[t["ip"]] = {
                    int(k): int(v) for k, v in t["cloud_ports"].items()}
            except Exception as e:
                print(f"  [!] cloud_ports for {t['id']} ignored: {e}")

        runner = core.Runner(
            t["ip"], None,
            on_log=lambda m: print(_colorize(str(m), args.no_color)),
            on_status=lambda *a: None)
        runner.concurrency = max(1, args.workers)
        runner.ctx.allow_active = bool(args.active)
        if s.get("ip"):
            runner.ctx.source_ip = s["ip"]

        # Device attribution: MyGovNet has many zones, each guarded by its own
        # appliance (Sangfor NGAF at the WAN/SDWAN site, Forcepoint + others
        # elsewhere). Tag the run with the appliance on THIS leg (target's
        # `appliance`, else the zone) so evidence/report says which device the
        # verdicts belong to — and the appliance-log ingester can be run per device.
        appliance = t.get("appliance") or t.get("zone") or ""
        try:
            ev = core.Evidence(base=os.path.join(base, f"{s.get('id','local')}__{t['id']}"))
            root = runner.run(selected, max(1, args.iterations), ev,
                              skip_unready=not args.force, recon=not args.no_recon,
                              mode=job_mode, site_id=appliance or None)
            counts = _verdict_counts(ev.records)
        except ValueError as e:                 # invalid target / allowlist refusal
            print(f"  [!] {t['id']} skipped: {e}")
            fleet_summary["jobs"].append({"source": s.get("id"), "target": t["id"],
                                          "ip": t["ip"], "error": str(e)})
            continue
        except KeyboardInterrupt:
            print("\n[!] interrupted", file=sys.stderr)
            break

        fleet_summary["jobs"].append({
            "source": s.get("id"), "source_ip": s.get("ip"),
            "target": t["id"], "ip": t["ip"], "zone": t.get("zone"),
            "appliance": appliance, "direction": j["direction"],
            "evidence": root, "verdicts": counts})
        print(_colorize("  -> " + ", ".join(f"[{k}]×{v}" for k, v in sorted(counts.items())),
                        args.no_color))

    fleet_summary["finished"] = datetime.now().isoformat()
    fleet_summary["harness_version"] = core.VERSION
    try:
        os.makedirs(base, exist_ok=True)
        core._atomic_write(os.path.join(base, "fleet_summary.json"),
                           lambda f: json.dump(fleet_summary, f, indent=2, default=str))
    except Exception as e:
        print(f"[!] could not write fleet_summary.json: {e}", file=sys.stderr)

    # fleet roll-up: any target where an attack PASSED is a finding
    findings = [jb for jb in fleet_summary["jobs"]
                if (jb.get("verdicts") or {}).get("SUCCESS")]
    print(f"\n=== FLEET DONE — {len(fleet_summary['jobs'])} job(s); "
          f"{len(findings)} with a PASSED attack (finding) ===")
    for jb in findings:
        print(_colorize(f"  [SUCCESS] {jb['source']} -> {jb['target']} ({jb['ip']}) "
                        f"x{jb['verdicts']['SUCCESS']}", args.no_color))
    print(f"Evidence: {base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
