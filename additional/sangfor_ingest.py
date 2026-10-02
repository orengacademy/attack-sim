#!/usr/bin/env python3
"""Ingest a Sangfor session-log export (.xlsx) and correlate it with the harness
modules — then (optionally) write a detections.json so attacks the appliance SAW
but let through are scored DETECTED (passed-but-alerted) instead of a silent
SUCCESS. That turns the harness's Blocked/Passed result into the full purple-team
Blocked / Detected / Passed-undetected picture.

Pure stdlib (an .xlsx is a zip of XML) — no openpyxl needed. Read-only on the
log; only touches detections.json when you pass --write.

Usage:
  python3 additional/sangfor_ingest.py --target 159.223.35.108
  python3 additional/sangfor_ingest.py --target 159.223.35.108 --write
  python3 additional/sangfor_ingest.py --log /path/to/log.xlsx --target <ip> --write

The Sangfor "Session Logs" export has a Results table with columns Date, Service,
Protocol, Src/Dst Zone, Source IP, Dst IP, Dst Port, Policy Name, Action, ...
We read Action (Allow/Deny) per (Protocol, Dst Port) for the target and map it to
the modules whose META ports match (honouring the cloud NAT aliases 445<->4445
and 135<->1135, since the AD modules reach the forwarded ports)."""
import argparse
import json
import os
import sys
import zipfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import loader  # noqa: E402

_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
# cloud NAT aliases: a module port <-> the forwarded port the Sangfor logs.
_PORT_ALIASES = {445: {445, 4445}, 135: {135, 1135}, 4445: {445, 4445}, 1135: {135, 1135}}


def _col_letter(ref):
    return "".join(ch for ch in ref if ch.isalpha())


def _load_rows(path):
    """Return (header_dict{name:col_letter}, [row_dict{name:value}]) from the
    first worksheet's 'Results' table."""
    z = zipfile.ZipFile(path)
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall(f"{_NS}si"):
            shared.append("".join(t.text or "" for t in si.iter(f"{_NS}t")))
    sheet = next(n for n in z.namelist() if n.startswith("xl/worksheets/sheet"))
    rows = ET.fromstring(z.read(sheet)).findall(f".//{_NS}row")

    def rowmap(row):
        out = {}
        for c in row.findall(f"{_NS}c"):
            v = c.find(f"{_NS}v")
            val = "" if v is None else (shared[int(v.text)] if c.get("t") == "s" else v.text)
            out[_col_letter(c.get("r"))] = val
        return out

    raw = [rowmap(r) for r in rows]
    # find the header row: the one that has both a "Dst IP" and an "Action" cell
    hidx = None
    for i, rm in enumerate(raw):
        vals = {v.strip() for v in rm.values()}
        if "Dst IP" in vals and "Action" in vals:
            hidx = i
            break
    if hidx is None:
        raise SystemExit("[!] could not find the Results header (no 'Dst IP'/'Action' row) — "
                         "is this a Sangfor Session Logs export?")
    header = {rm_val.strip(): col for col, rm_val in raw[hidx].items() if rm_val.strip()}
    data = []
    for rm in raw[hidx + 1:]:
        rec = {name: rm.get(col, "") for name, col in header.items()}
        if rec.get("Dst IP"):
            data.append(rec)
    return header, data


def _port_actions(data, target):
    """{(proto_lower, int_port): Counter{action:n}} for sessions to `target`."""
    import collections
    pa = collections.defaultdict(collections.Counter)
    meta = collections.defaultdict(dict)   # (proto,port) -> {policy, service}
    for r in data:
        if target and r.get("Dst IP") != target:
            continue
        proto = (r.get("Protocol") or "").strip().lower()
        try:
            port = int((r.get("Dst Port") or "").strip())
        except ValueError:
            continue
        action = (r.get("Action") or "").strip() or "?"
        pa[(proto, port)][action] += 1
        meta[(proto, port)].setdefault("policy", r.get("Policy Name", ""))
        meta[(proto, port)].setdefault("service", r.get("Service", ""))
    return pa, meta


def _actions_for(pa, proto, port):
    """Merge action counts across the port's cloud aliases."""
    import collections
    merged = collections.Counter()
    for p in _PORT_ALIASES.get(port, {port}):
        merged += pa.get((proto, p), collections.Counter())
    return merged


def main():
    ap = argparse.ArgumentParser(description="Correlate a Sangfor session log with the harness modules.")
    ap.add_argument("--log", default="/home/oreng/sangfor-log.xlsx", help="path to the Sangfor .xlsx export")
    ap.add_argument("--target", help="target Dst IP to correlate (recommended)")
    ap.add_argument("--model", default="Sangfor M4500-F-1", help="appliance name recorded as the detection source")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "detections.json"))
    ap.add_argument("--write", action="store_true", help="merge results into detections.json (default: dry-run)")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        raise SystemExit(f"[!] log not found: {args.log}")
    header, data = _load_rows(args.log)
    print(f"Parsed {len(data)} session rows from {os.path.basename(args.log)}")
    pa, pmeta = _port_actions(data, args.target)
    tgt_rows = sum(sum(c.values()) for c in pa.values())
    print(f"Target {args.target or '(all)'}: {tgt_rows} session(s) across {len(pa)} (proto,port) pairs\n")

    # appliance posture table
    print("Sangfor posture for the target (per proto/port):")
    for (proto, port), c in sorted(pa.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        verdict = "DENY" if c.get("Deny") and not c.get("Allow") else (
            "ALLOW" if c.get("Allow") and not c.get("Deny") else "MIXED")
        print(f"  {proto:4}/{port:<6} {verdict:<6} {dict(c)}  "
              f"policy={pmeta[(proto, port)].get('policy', '')}")
    print()

    # correlate with modules
    detections = {}
    print(f"{'MODULE':26} {'PORT(S)':14} {'SANGFOR':8} INTERPRETATION")
    print("-" * 92)
    for m in sorted(loader.discover(), key=lambda x: x.META["id"]):
        meta = m.META
        ports = meta.get("ports", []) or []
        if not ports:
            continue   # egress-only module — dst isn't the target, skip auto-correlation
        seen = {}
        for spec in ports:
            proto, port = spec if isinstance(spec, (list, tuple)) else ("tcp", spec)
            if proto == "icmp" or port is None:
                continue
            c = _actions_for(pa, proto, port)
            if c:
                seen[f"{proto}/{port}"] = c
        if not seen:
            continue
        allow = sum(c.get("Allow", 0) for c in seen.values())
        deny = sum(c.get("Deny", 0) for c in seen.values())
        if deny and not allow:
            sang, interp = "DENY", "appliance BLOCKED it (corroborates/EXPLAINS a BLOCKED verdict)"
        elif allow and not deny:
            sang, interp = "ALLOW", "appliance SAW + PERMITTED it -> a SUCCESS here should score DETECTED (seen, not prevented)"
        else:
            sang, interp = "MIXED", "appliance both allowed and denied (per-port/time) — review"
        ports_s = ",".join(seen.keys())
        print(f"{meta['id']:26} {ports_s:14} {sang:<8} {interp}")
        # record a detection entry for anything the appliance LOGGED (it SAW the
        # attack). The DETECTED verdict only applies when the attack PASSED, so a
        # DENY entry is harmless (it just carries the truth in the note).
        note = (f"Sangfor session-logged {ports_s}: {sang} "
                f"(policy={';'.join(sorted({pmeta[(sp.split('/')[0], int(sp.split('/')[1]))].get('policy','') for sp in seen}))})")
        detections[meta["id"]] = {"source": args.model, "note": note}

    print()
    if not detections:
        print("No module ports matched the log for this target — nothing to write.")
        return 0

    if args.write:
        existing = {}
        if os.path.exists(args.out):
            try:
                with open(args.out) as f:
                    existing = json.load(f)
            except Exception:
                existing = {}
        if not isinstance(existing, dict):
            existing = {}
        existing.update(detections)
        with open(args.out, "w") as f:
            json.dump(existing, f, indent=2)
        print(f"[written] {len(detections)} detection(s) merged into {args.out}")
        print("Next run scores any of these that PASS as DETECTED (passed-but-seen). "
              "Point the harness at it with HARNESS_DETECTIONS or keep it as detections.json.")
    else:
        print(f"[dry-run] {len(detections)} detection(s) would be written to {args.out} "
              "(re-run with --write). Preview:")
        print(json.dumps(detections, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
