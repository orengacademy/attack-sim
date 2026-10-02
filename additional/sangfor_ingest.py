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

# IPS/threat-log "Attack Type" free-text -> module id(s). First match wins per
# event; a generic "web Vulnerability" maps to both web-server exploits.
_IPS_MAP = [
    (r"icmp.*flood", ["icmp_flood"]),
    (r"syn.*flood|tcp.*flood", ["syn_flood"]),
    (r"log4|jndi", ["log4shell"]),
    (r"web\s*vuln|path\s*traversal|directory\s*traversal|apache|cgi", ["apache_41773", "log4shell"]),
    (r"ssh.*brute|brute.*ssh", ["ssh_brute"]),
    (r"snmp", ["snmp_brute"]),
    (r"ftp", ["ftp_anonymous"]),
    (r"ldap", ["ldap_null_bind"]),
    (r"kerber", ["kerberoast", "kerberos_asrep", "nopac"]),
    (r"smb|psexec|wmi|lateral|dce.?rpc", ["psexec", "wmiexec", "dcsync"]),
    (r"dns.*tunnel", ["dns_tunnel"]),
    (r"brute", ["ssh_brute"]),
    (r"flood|dos|ddos", ["icmp_flood", "syn_flood"]),
]


# Column-name synonyms -> the canonical names the code uses, so the SAME parser
# handles Sangfor, Forcepoint, and other vendors' exports (their headers differ).
# Drop a new vendor's header spellings here when you get a sample export.
_CANON = {
    "dst ip": "Dst IP", "dst address": "Dst IP", "destination": "Dst IP",
    "destination ip": "Dst IP", "dest ip": "Dst IP", "dstip": "Dst IP", "dst": "Dst IP",
    "action": "Action", "disposition": "Action", "act": "Action", "result": "Action",
    "dst port": "Dst Port", "destination port": "Dst Port", "dest port": "Dst Port",
    "dport": "Dst Port", "dst_port": "Dst Port", "port": "Dst Port",
    "protocol": "Protocol", "proto": "Protocol", "ip protocol": "Protocol", "transport": "Protocol",
    "attack type": "Attack Type", "threat name": "Attack Type", "situation": "Attack Type",
    "signature": "Attack Type", "threat": "Attack Type", "attack": "Attack Type",
    "threat level": "Threat Level", "severity": "Threat Level", "risk": "Threat Level",
    "service": "Service", "application": "Application", "app": "Application",
    "policy name": "Policy Name", "policy": "Policy Name", "rule name": "Policy Name", "rule": "Policy Name",
    "type": "Type", "log type": "Type", "src address": "Src Address",
    "source ip": "Src Address", "src ip": "Src Address",
    # Forcepoint NGFW/SMC + Web spellings
    "dst addr": "Dst IP", "src addr": "Src Address", "rule tag": "Policy Name",
    "category": "Attack Type", "sender domain": "Dst IP",
}

# Action VALUES differ by vendor too (Sangfor Allow/Deny; Forcepoint NGFW
# Permit/Discard/Refuse/Terminate; Web Permitted/Blocked). Normalise to Allow/Deny.
_ALLOW_WORDS = {"allow", "allowed", "permit", "permitted", "accept", "accepted", "pass", "passed"}
_DENY_WORDS = {"deny", "denied", "block", "blocked", "drop", "dropped", "discard", "discarded",
               "refuse", "refused", "reject", "rejected", "terminate", "terminated", "prevent",
               "prevented", "reset"}


def _canon_action(val):
    v = (val or "").strip().lower()
    if v in _ALLOW_WORDS:
        return "Allow"
    if v in _DENY_WORDS:
        return "Deny"
    # partial match (e.g. "deny in associated policy", "discard (ips)")
    if any(w in v for w in _DENY_WORDS):
        return "Deny"
    if any(w in v for w in _ALLOW_WORDS):
        return "Allow"
    return (val or "?").strip() or "?"


def _canon(name):
    return _CANON.get((name or "").strip().lower(), (name or "").strip())


def _col_index(ref):
    """0-based column index from an A1 cell ref (e.g. 'AB12' -> 27)."""
    n = 0
    for ch in ref:
        if ch.isalpha():
            n = n * 26 + (ord(ch.upper()) - 64)
    return n - 1


def _read_xlsx(path):
    """First worksheet as a list of row lists (gap-filled by column index)."""
    z = zipfile.ZipFile(path)
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall(f"{_NS}si"):
            shared.append("".join(t.text or "" for t in si.iter(f"{_NS}t")))
    sheet = next(n for n in z.namelist() if n.startswith("xl/worksheets/sheet"))
    out = []
    for row in ET.fromstring(z.read(sheet)).findall(f".//{_NS}row"):
        cells = {}
        maxi = -1
        for c in row.findall(f"{_NS}c"):
            i = _col_index(c.get("r", "A1"))
            v = c.find(f"{_NS}v")
            cells[i] = "" if v is None else (shared[int(v.text)] if c.get("t") == "s" else v.text)
            maxi = max(maxi, i)
        out.append([cells.get(i, "") for i in range(maxi + 1)])
    return out


def _read_csv(path):
    import csv
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        return [list(r) for r in csv.reader(f)]


def _load_rows(path):
    """Parse a Sangfor/Forcepoint/other export (.xlsx or .csv) and return
    (canonical_header[list], [row_dict{canonical_name: value}]). Finds the header
    row by content (an 'Action' column + a destination column) so vendor preamble
    rows are skipped, and normalises column names via _CANON so downstream code is
    vendor-independent."""
    rows = _read_csv(path) if path.lower().endswith(".csv") else _read_xlsx(path)
    hidx = header = None
    for i, row in enumerate(rows):
        canon = [_canon(c) for c in row]
        if "Action" in canon and "Dst IP" in canon:
            hidx, header = i, canon
            break
    if hidx is None:
        raise SystemExit("[!] could not find a results header (need an 'Action' column and a "
                         "destination column like 'Dst IP'/'Dst Address'/'Destination'). "
                         "If this is a new vendor export, add its header spellings to _CANON.")
    data = []
    for row in rows[hidx + 1:]:
        rec = {}
        for name, val in zip(header, row):
            if name:
                rec.setdefault(name, val)
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
        action = _canon_action(r.get("Action"))
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


def _map_attack_type(attack_type):
    import re
    at = (attack_type or "").lower()
    for pat, mods in _IPS_MAP:
        if re.search(pat, at):
            return mods
    return []


def ingest_ips(path, target, model):
    """Parse a Sangfor IPS/threat-log .xlsx (WAF / Intrusion Prevention / Anti-DoS)
    and map each 'Attack Type' hit against the target to module id(s). Returns
    (detections{id:{source,note}}, events[dict]). These are SIGNATURE-level and
    take precedence over the session-log correlation."""
    import collections
    _h, data = _load_rows(path)
    events = []
    per_mod = collections.defaultdict(lambda: collections.Counter())
    per_mod_meta = collections.defaultdict(lambda: {"types": set(), "levels": set()})
    for r in data:
        dst = r.get("Dst Address") or r.get("Dst IP") or ""
        if target and dst != target:
            continue
        at = r.get("Attack Type", "")
        action = _canon_action(r.get("Action"))
        level = (r.get("Threat Level") or "").strip()
        typ = (r.get("Type") or "").strip()
        mods = _map_attack_type(at)
        events.append({"attack_type": at, "type": typ, "action": action,
                       "level": level, "modules": mods})
        for mid in mods:
            per_mod[mid][action] += 1
            per_mod_meta[mid]["types"].add(at)
            per_mod_meta[mid]["levels"].add(level)
    dets = {}
    for mid, actions in per_mod.items():
        deny = actions.get("Deny", 0)
        allow = actions.get("Allow", 0)
        verb = "DENY" if deny and not allow else ("ALLOW" if allow and not deny else "MIXED")
        types = ", ".join(sorted(t for t in per_mod_meta[mid]["types"] if t))
        levels = "/".join(sorted(x for x in per_mod_meta[mid]["levels"] if x))
        dets[mid] = {"source": model,
                     "note": f"Sangfor IPS signature fired: '{types}' [{levels}] {verb} "
                             f"x{deny + allow} (prevention={'yes' if deny else 'no'})"}
    return dets, events


def main():
    ap = argparse.ArgumentParser(
        description="Correlate an SD-WAN/firewall log (Sangfor, Forcepoint, …) with the "
                    "harness modules and emit detections.json. .xlsx or .csv; column names "
                    "are matched by synonym (see _CANON) so it's vendor-independent.")
    ap.add_argument("--log", default="", help="session/traffic-log export (.xlsx/.csv) — per-port Allow/Deny")
    ap.add_argument("--ips", help="IPS/threat-log export (.xlsx/.csv) — signature-level; takes precedence")
    ap.add_argument("--target", help="target Dst IP to correlate (recommended)")
    ap.add_argument("--model", "--vendor", dest="model", default="Sangfor M4500-F-1",
                    help="appliance name recorded as the detection source (e.g. 'Forcepoint NGFW')")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "detections.json"))
    ap.add_argument("--write", action="store_true", help="merge results into detections.json (default: dry-run)")
    args = ap.parse_args()

    if not args.log and not args.ips:
        raise SystemExit("[!] pass --log (session export) and/or --ips (threat export)")
    detections = {}

    # ---- session-log correlation (per-port Allow/Deny) -----------------------
    have_session = args.log and os.path.exists(args.log)
    if args.log and not have_session:
        print(f"[warn] session log not found: {args.log} (skipping)")
    if have_session:
        _header, data = _load_rows(args.log)
        print(f"Parsed {len(data)} session rows from {os.path.basename(args.log)}")
        pa, pmeta = _port_actions(data, args.target)
        tgt_rows = sum(sum(c.values()) for c in pa.values())
        print(f"Target {args.target or '(all)'}: {tgt_rows} session(s) across {len(pa)} (proto,port) pairs\n")
        print(f"{args.model} posture for the target (per proto/port):")
        for (proto, port), c in sorted(pa.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            verdict = "DENY" if c.get("Deny") and not c.get("Allow") else (
                "ALLOW" if c.get("Allow") and not c.get("Deny") else "MIXED")
            print(f"  {proto:4}/{port:<6} {verdict:<6} {dict(c)}  "
                  f"policy={pmeta[(proto, port)].get('policy', '')}")
        print()
        detections.update(_session_detections(pa, pmeta, args.model))

    # ---- IPS/threat-log correlation (signature-level — takes precedence) -----
    if args.ips:
        if not os.path.exists(args.ips):
            raise SystemExit(f"[!] IPS log not found: {args.ips}")
        ips_dets, events = ingest_ips(args.ips, args.target, args.model)
        print(f"IPS/threat events for the target: {len(events)}")
        import collections
        tally = collections.Counter((e["attack_type"], e["action"]) for e in events)
        for (at, act), n in tally.most_common():
            mods = _map_attack_type(at)
            print(f"  {act:<6} {at:<28} -> {', '.join(mods) or '(unmapped)'}  x{n}")
        print()
        detections.update(ips_dets)   # signature-level wins over session-level

    if not detections:
        print("No module matched the log(s) for this target — nothing to write.")
        return 0
    return _emit(detections, args)


def _session_detections(pa, pmeta, model):
    """Per-port Allow/Deny correlation -> {id:{source,note}} (printed as it goes)."""
    detections = {}
    print(f"{'MODULE':26} {'PORT(S)':14} {'SEEN':8} INTERPRETATION")
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
        policies = ';'.join(sorted({pmeta[(sp.split('/')[0], int(sp.split('/')[1]))].get('policy', '') for sp in seen}))
        detections[meta["id"]] = {"source": model,
                                  "note": f"session-logged {ports_s}: {sang} (policy={policies})"}
    print()
    return detections


def _emit(detections, args):
    """Write/merge detections.json (with --write) or print a dry-run preview."""
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
