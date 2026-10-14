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
purple-team convention: RED = attack got through (finding), GREEN =
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
    "DETECTED":       ("\033[38;5;208m", "◐"),  # orange — passed but SOC alerted
    "BLOCKED":        ("\033[32m", "■"),   # green  — control worked
    "NOT-VULNERABLE": ("\033[92m", "◆"),   # bright-green diamond (single-width, aligns with ●■○) — service reached, target hardened
    "NO-SERVICE":     ("\033[34m", "○"),   # blue   — port closed, not a block
    "AUTH-FAILED":    ("\033[33m", "▲"),   # amber  — bad creds
    "NO-RESULT":      ("\033[33m", "?"),   # amber  — review
    "INCONCLUSIVE":   ("\033[35m", "◌"),   # purple — source in IPS quarantine, not tested
    "SKIPPED":        ("\033[90m", "–"),   # grey   — did nothing
    "PREREQ-MISSING": ("\033[90m", "–"),
}
_VERDICT_ORDER = ["SUCCESS", "DETECTED", "BLOCKED", "NOT-VULNERABLE", "NO-SERVICE",
                  "AUTH-FAILED", "NO-RESULT", "INCONCLUSIVE", "SKIPPED", "PREREQ-MISSING"]
# one-letter code per verdict for the compact per-iteration ITER column —
# the aggregate VERDICT column only ever shows the single most-significant
# iteration (_VERDICT_ORDER), which hid a later iteration landing in a
# different bucket (e.g. icmp_flood's loss-delta sometimes falling in the
# ambiguous band on one run and not another).
_ITER_CODE = {"SUCCESS": "S", "DETECTED": "D", "BLOCKED": "B", "NOT-VULNERABLE": "V",
              "NO-SERVICE": "O", "AUTH-FAILED": "A", "NO-RESULT": "N",
              "INCONCLUSIVE": "I", "SKIPPED": "-", "PREREQ-MISSING": "-"}

_ANSI = {
    "SUCCESS": "\033[31m",   # red — got through undetected (finding)
    "DETECTED": "\033[38;5;208m",                   # orange — passed but SOC alerted
    "BLOCKED": "\033[32m",                          # green — control worked
    "NOT-VULNERABLE": "\033[92m",                   # bright green — service reached, target hardened
    "NO-SERVICE": "\033[34m",                       # blue — port closed, not a block
    "AUTH-FAILED": "\033[33m", "NO-RESULT": "\033[33m",  # amber — review
    "INCONCLUSIVE": "\033[35m",                          # purple — IPS quarantine, not tested
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


# Target-INDEPENDENT "egress" modules test the attacker's own egress path (to the
# internet / your infra), not the named target — so in a multi-target scan they
# run ONCE (on the first target), not repeated per target where only Kali's egress
# state would vary. No target port, excluding the few no-port modules that still
# probe the target/internal.
_TARGET_TOUCHING_NO_PORTS = {"stateful_evasion", "segmentation_sweep", "switch_mgmt",
                             "appid_port_mismatch", "ipv6_acl_parity"}


def _is_egress(m):
    return not (m.META.get("ports") or []) and m.META["id"] not in _TARGET_TOUCHING_NO_PORTS


def _select(modules, args):
    if args.only:
        want = {x.strip() for x in args.only.split(",") if x.strip()}
        sel = [m for m in modules if m.META["id"] in want]
        missing = want - {m.META["id"] for m in sel}
        if missing:
            print(f"[!] unknown module id(s): {', '.join(sorted(missing))}", file=sys.stderr)
        return sel
    # base set. DEFAULT = the original 10-module baseline (same as the GUI's
    # default tick) — a bare `cli.py --target X` runs a sensible, fast,
    # self-contained set rather than all of them. Use --all for everything.
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
        # "both" = run EVERY direction (a2b + b2a + both), not only the modules
        # literally tagged direction="both". For a one-way filter (a2b / b2a) a
        # module tagged "both" still matches (it runs in that direction too).
        if d != "both":
            sel = [m for m in sel
                   if m.META.get("direction", "a2b").lower() in (d, "both")]
    return sel


def _c(s, color, no_color):
    return s if no_color or not sys.stdout.isatty() else f"{color}{s}{_RESET}"


def _egress_ip(target):
    """Best-effort LOCAL egress IP the OS would use to reach `target` — the address
    the attack traffic actually leaves from. A UDP connect only selects the route
    (no packets sent); returns '' on failure (IPv6/hostname/unroutable)."""
    import socket as _s
    try:
        k = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        try:
            k.connect((str(target), 80))
            return k.getsockname()[0]
        finally:
            k.close()
    except Exception:
        return ""


DIM = "\033[2m"; BOLD = "\033[1m"; ACC = "\033[36m"; AMBER = "\033[33m"
CYAN_B = "\033[96m"; BLUE = "\033[34m"; GREEN = "\033[32m"; GREEN_B = "\033[92m"
MAGENTA = "\033[35m"; GREY = "\033[90m"

# compact 3-row block wordmark for the banner logo (letters used by "ATTACK SIM")
_LOGO_GLYPHS = {
    "A": ["\u2584\u2580\u2588", "\u2588\u2580\u2588", "\u2580 \u2580"],
    "T": ["\u2580\u2588\u2580", " \u2588 ", " \u2580 "],
    "C": ["\u2584\u2580\u2580", "\u2588  ", "\u2580\u2580\u2580"],
    "K": ["\u2588 \u2588", "\u2588\u2588 ", "\u2580 \u2580"],
    "S": ["\u2584\u2580\u2580", "\u2580\u2580\u2584", "\u2580\u2580 "],
    "I": ["\u2588", "\u2588", "\u2580"],
    "M": ["\u2588\u2584 \u2584\u2588", "\u2588 \u2580 \u2588", "\u2580   \u2580"],
    " ": ["  ", "  ", "  "],
}


def _truecolor():
    if os.environ.get("NO_COLOR"):
        return False
    return "truecolor" in os.environ.get("COLORTERM", "") or "24bit" in os.environ.get("COLORTERM", "")


def _grad_row(text, start=(34, 211, 238), end=(99, 102, 241)):
    """Per-character cyan->indigo truecolor gradient across one row (bold)."""
    n = max(1, len(text) - 1)
    out = []
    for i, ch in enumerate(text):
        if ch == " ":
            out.append(ch); continue
        r = int(start[0] + (end[0] - start[0]) * i / n)
        g = int(start[1] + (end[1] - start[1]) * i / n)
        b = int(start[2] + (end[2] - start[2]) * i / n)
        out.append(f"\033[1;38;2;{r};{g};{b}m{ch}")
    return "".join(out) + _RESET


def _logo_lines(no_color, word="ATTACK SIM"):
    """The 3-row block wordmark, gradient-coloured when the terminal supports it."""
    rows = ["", "", ""]
    for ch in word:
        g = _LOGO_GLYPHS.get(ch.upper(), _LOGO_GLYPHS[" "])
        for i in range(3):
            rows[i] += g[i] + " "
    tty = sys.stdout.isatty()
    if no_color or not tty:
        return rows
    if _truecolor():
        return [_grad_row(r) for r in rows]
    return [f"{CYAN_B}{BOLD}{r}{_RESET}" for r in rows]


def _print_logo(no_color):
    print()
    for ln in _logo_lines(no_color):
        print("  " + ln)
    print("  " + _c("Breach & Attack Simulation", DIM, no_color)
          + _c("  \u00b7  ", GREY, no_color)
          + _c("MyGovNet", CYAN_B, no_color)
          + _c("  \u00b7  ", GREY, no_color)
          + _c(f"v{core.VERSION}", DIM, no_color))


def _fmt_recon(s):
    """'None/icmp:up, 21/tcp:open, …' -> 'icmp · tcp 21 22 … · udp 161' (reachable only)."""
    import re as _re
    tcp, udp, icmp = [], [], False
    for tok in s.split(","):
        m = _re.match(r"\s*(\S+?)/(\w+):(\w+)", tok)
        if not m:
            continue
        port, proto, state = m.groups()
        if proto == "icmp" and state in ("up", "open"):
            icmp = True
        elif state == "open" and proto == "tcp":
            tcp.append(port)
        elif state == "open" and proto == "udp":
            udp.append(port)
    bits = []
    if icmp:
        bits.append("icmp")
    if tcp:
        bits.append("tcp " + " ".join(tcp))
    if udp:
        bits.append("udp " + " ".join(udp))
    return " · ".join(bits) or s


def _setup_panel(buf, args, run_info=None):
    """Render the engine's setup log (platform / preflight / recon / policy) as a
    tidy labelled 'command-center' panel instead of flat lines. Defensive: any
    buffered line not recognised is printed dim afterwards, so nothing is lost."""
    import re as _re
    nc = args.no_color
    W = 72
    used = set()

    def first(pat):
        for i, l in enumerate(buf):
            m = _re.search(pat, l)
            if m:
                used.add(i)
                return m
        return None

    def sect(label):
        lab = " " + label + " "
        print("  " + _c("╶─", ACC, nc) + _c(lab, CYAN_B + BOLD, nc)
              + _c("─" * max(2, W - len(lab) - 3) + "╴", DIM, nc))

    def kv(k, v, vcol=None):
        if not v:
            return
        print("     " + _c(f"{k:<11}", DIM, nc) + " " + (_c(str(v), vcol, nc) if vcol else str(v)))

    plat = first(r"^Platform:\s*(.+)")
    pre = first(r"^Preflight:\s*(.+?)\.?$")
    act = first(r"^ACTIVE-ESTABLISHMENT:\s*(\w+)")
    det = first(r"^Blue-team detections loaded:\s*(\d+)")
    ev = first(r"^Evidence dir:\s*(.+)")
    src = first(r"^Source IP \(egress bind\):\s*(.+)")
    first(r"^Path:\s")           # consume (low value)

    if plat or pre or ev:
        sect("ENVIRONMENT")
        if plat:
            parts = [p.strip() for p in plat.group(1).split("|")]
            kv("platform", parts[0] if parts else "")
            rt = []
            for p in parts[1:]:
                p = p.replace("privilege:", "").replace("pkg mgr:", "").replace("Python", "py").strip()
                if p:
                    rt.append(p)
            if pre:
                rt.append("preflight " + pre.group(1))
            if rt:
                kv("runtime", " · ".join(rt))
        elif pre:
            kv("preflight", pre.group(1))
        tail = []
        if ev:
            tail.append(ev.group(1))
        if act:
            tail.append("active " + act.group(1))
        if det:
            tail.append(det.group(1) + " detections")
        if tail:
            kv("evidence", " · ".join(tail))
        if src:
            kv("source", src.group(1), ACC)

    rec = first(r"^Recon \(reachability of ([^)]+)\):\s*(.+)")
    warn = first(r"^\[WARN\] recon")
    sug = first(r"^\s*suggested[^:]*:\s*(.+)")
    can = first(r"^\s*canary[^:]*:\s*(.+)")
    nre = first(r"^\s*not reachable[^:]*:\s*(.+)")
    if rec or warn:
        sect("RECON" + (f" · {rec.group(1)}" if rec else ""))
        if rec:
            kv("reachable", _fmt_recon(rec.group(2)), ACC)
        if warn:
            kv("recon", "DISABLED (--no-recon) — port state unverified", AMBER)
        if sug:
            items = [x.strip() for x in sug.group(1).split(",") if x.strip()]
            kv("suggested", " · ".join(items[:6]) + (f"   (+{len(items) - 6} more)" if len(items) > 6 else ""))
        if can:
            kv("canary", can.group(1))
        if nre:
            n = len([x for x in nre.group(1).split(",") if x.strip()])
            kv("filtered", f"{n} not reachable (run anyway — a filtered port may BE the control)")

    pol = first(r"^Port policy \[([^\]]+)\][^:]*:\s*(.+)")
    den = first(r"^\s*policy-denied[^:]*:\s*(.+)")
    if pol:
        body = pol.group(2)
        a = _re.search(r"(\d+) on ALLOWED", body)
        d = _re.search(r"(\d+) on DENIED", body)
        e = _re.search(r"(\d+) egress", body)
        sect("POLICY · " + pol.group(1))
        cnt = [x for x in ((a.group(1) + " allowed" if a else ""),
                           (d.group(1) + " denied" if d else ""),
                           (e.group(1) + " n/a" if e else "")) if x]
        kv("ports", " · ".join(cnt))
        if den:
            kv("expect-block", den.group(1), AMBER)

    priv = first(r"^Privilege:\s*(.+)")
    privwarn = first(r"^\[WARN\] not root.+")
    if run_info:
        n_mods, iters, workers = run_info
        sect("RUN")
        kv("battery", f"{n_mods} module(s) × {iters} iter · {workers} workers")
        if priv:
            # "root-needing modules (ICMP Flood (DoS)) — running as root/admin" -> tidy kv
            pv = priv.group(1).replace("root-needing modules ", "root-needing: ")
            kv("privilege", pv, ACC if "running as root" in pv else AMBER)
        if privwarn:
            kv("privilege", privwarn.group(0)[6:].strip(), AMBER)

    # fallback — show any buffered line we didn't fold into a section (dim), so a
    # wording change can't silently drop setup info.
    for i, l in enumerate(buf):
        if i not in used and l.strip() and not l.strip().startswith("Target:"):
            print(_c("     " + l.strip(), DIM, nc))

# one-line human gloss per verdict, for the table's DETAIL column
_VERDICT_GLOSS = {
    "SUCCESS":        "got through — undetected (finding)",
    "DETECTED":       "got through but SOC alerted",
    "BLOCKED":        "control worked — attack stopped",
    "NOT-VULNERABLE": "not vulnerable — service reached, target hardened (no finding)",
    "NO-SERVICE":     "port closed — service not present",
    "AUTH-FAILED":    "bad credentials — fix creds",
    "NO-RESULT":      "inconclusive — review raw log",
    "INCONCLUSIVE":   "indeterminate — can't decide (quarantine / unobservable callback)",
    "SKIPPED":        "did nothing — n/a or unconfigured",
    "PREREQ-MISSING": "prerequisite missing — not run",
}
# short form of the same gloss, for the per-iteration ITERATIONS column where
# N copies of it (one per iteration) have to fit in one table cell.
_VERDICT_GLOSS_SHORT = {
    "SUCCESS": "finding", "DETECTED": "SOC alerted",
    "BLOCKED": "blocked", "NOT-VULNERABLE": "secured", "NO-SERVICE": "no service", "AUTH-FAILED": "bad creds",
    "NO-RESULT": "review log", "INCONCLUSIVE": "indeterminate",
    "SKIPPED": "skipped", "PREREQ-MISSING": "missing prereq",
}


def _cell(text, w, color, no_color):
    """A fixed-width table cell: truncate, pad, then colour the whole cell (ANSI
    codes don't count toward width because padding happens first)."""
    text = "" if text is None else str(text)
    if len(text) > w:
        text = text[:w - 1] + "…"
    text = f"{text:<{w}}"
    return _c(text, color, no_color) if color else text


def _clock(ts):
    """ISO timestamp -> human-readable 'YYYY-MM-DD HH:MM:SS' (date + time), or '' when unparseable."""
    if not ts:
        return ""
    try:
        import datetime as _dt
        return _dt.datetime.fromisoformat(str(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return str(ts)[:19].replace("T", " ")


def _print_summary(ev, args, no_color, elapsed, target=None):
    """Modern end-of-run summary from the evidence records: a verdict-distribution
    strip plus one aligned, colour-coded TABLE of every module's result."""
    target = target or args.target
    recs = getattr(ev, "records", []) or []
    # aggregate per module across iterations (most-significant verdict wins)
    by_mod = {}
    for r in recs:
        mid = r.get("attack_id") or r.get("attack")
        d = by_mod.setdefault(mid, {"name": r.get("attack", mid), "cat": r.get("category", ""),
                                    "mitre": ", ".join(r.get("mitre", []) or []),
                                    "cwe": ", ".join(r.get("cwe", []) or []),
                                    "ports": r.get("ports", "") or "", "policy": r.get("policy", "") or "",
                                    "dir": r.get("direction", ""), "vs": [],
                                    "verdicts": {}, "outputs": {}, "iters": []})
        br = r.get("baseline_result", "?")
        d["vs"].append(br)
        d["verdicts"][br] = r.get("verdict", "")
        d["outputs"][br] = r.get("output", "") or ""
        d["iters"].append((r.get("iteration"), br))
        if r.get("duration_s") is not None:
            d["dur"] = max(d.get("dur", 0.0), r["duration_s"])
        if r.get("timestamp"):
            d["ts"] = r["timestamp"]       # per-module completion time (latest wins)
    for d in by_mod.values():
        d["v"] = next((v for v in _VERDICT_ORDER if v in d["vs"]), (d["vs"] or ["?"])[0])

    dist = {}
    for d in by_mod.values():
        dist[d["v"]] = dist.get(d["v"], 0) + 1
    n = len(by_mod)

    # ---- results: compute layout first (widths + details) so every rule spans
    #      the FULL content width -------------------------------------------------
    debug = getattr(args, "debug", False)
    show_iters = args.iterations > 1
    rows = sorted(by_mod.values(),
                  key=lambda x: (x["cat"],
                                 _VERDICT_ORDER.index(x["v"]) if x["v"] in _VERDICT_ORDER else 9,
                                 x["name"]))
    num_w = max(2, len(str(len(rows))))
    name_w = min(40, max((len(d["name"]) for d in rows), default=10))
    port_w = min(18, max((len((d.get("ports") or "")) for d in rows), default=5))
    mitre_w = min(22, max((len((d.get("mitre") or "")) for d in rows), default=5))
    cwe_w = min(9, max((len((d.get("cwe") or "")) for d in rows), default=3))

    def _hhmmss(ts):
        c = _clock(ts) or ""
        return c[-8:] if len(c) >= 8 else c

    def _detail_of(d):
        detail = _VERDICT_GLOSS.get(d["v"], "")
        if d["v"] == "BLOCKED":
            vtext = d["verdicts"].get("BLOCKED", "") or ""
            otext = d["outputs"].get("BLOCKED", "") or ""
            if "REJECTION RESPONSE" in vtext:
                detail = "rejection block (in-path IPS/WAF or host)"
            elif "BLOCKED-RATELIMIT" in otext:
                detail = "rate-limited/shaped \u2014 single-source; may be host/edge limit (see verdict)"
            if "whitebox-anomaly" in vtext:
                detail = "whitebox anomaly \u2014 service-down / edge / host filter, not a control"
        elif d["v"] == "NO-SERVICE":
            nvtext = d["verdicts"].get("NO-SERVICE", "") or ""
            if "attack vector" in nvtext or "key-only" in nvtext or "password auth" in nvtext.lower():
                detail = "no vector \u2014 SSH password auth disabled (key-only)"
        elif d["v"] == "NOT-VULNERABLE":
            nvt = (d["verdicts"].get("NOT-VULNERABLE", "") or "").lower()
            if "key-only" in nvt or "password auth" in nvt:
                detail = "secured \u2014 SSH key-only (brute-force N/A)"
            elif "community" in nvt or "snmp" in nvt:
                detail = "secured \u2014 no default SNMP community (hygiene holds)"
            else:
                detail = "not vulnerable \u2014 service reached, target hardened"
        if show_iters:
            iters_sorted = sorted((it for it in d["iters"] if it[0] is not None),
                                  key=lambda it: it[0])
            detail = " | ".join(f"{it}:{vv} ({_VERDICT_GLOSS_SHORT.get(vv, '?')})"
                                for it, vv in iters_sorted)
        if len(detail) > 60:
            detail = detail[:59] + "\u2026"
        return detail

    for d in rows:
        d["_detail"] = _detail_of(d)
    detail_w = max(len("DETAIL"), min(60, max((len(d["_detail"]) for d in rows), default=6)))
    # full printed row width: leading 2 + # + ' \u2590 ' (3) + chip16 + each 2-space gap + detail
    content_w = 2 + num_w + 3 + 16 + 2 + name_w + 2 + port_w + 2 + mitre_w + 2 + cwe_w + 2 + 8 + 2 + detail_w

    # ---- header: title + a full-width rule --------------------------------------
    site = (getattr(ev, "meta", {}) or {}).get("site_id") or getattr(args, "site_id", None)
    _meta = getattr(ev, "meta", {}) or {}
    _mode = _meta.get("mode") or (args.mode or "blackbox")
    _src = _meta.get("source_ip") or ""
    _cloud = _meta.get("cloud")
    _net = "cloud" if _cloud else ("on-prem" if _cloud is not None else "")
    _dest = f"{_src} \u2192 {target}" if _src else str(target)
    bits = [_dest, _mode] + ([_net] if _net else []) \
        + [f"{n} modules \u00d7 {args.iterations} iter", f"{elapsed:.0f}s"]
    if site:
        bits.append(f"site {site}")
    if debug:
        bits.append("DEBUG")
    print()
    print("  " + _c("RESULTS", BOLD, no_color) + _c("    " + "  \u00b7  ".join(bits), DIM, no_color))
    print("  " + _c("\u2501" * (content_w - 2), ACC, no_color))

    # ---- SCOREBOARD: one stacked proportional bar + count chips -----------------
    present = [v for v in _VERDICT_ORDER if v in dist]
    BARW = content_w - 2
    segs, used = [], 0
    for i, v in enumerate(present):
        col, _ic = _VERDICT_STYLE.get(v, ("", "\u2022"))
        w = (BARW - used) if i == len(present) - 1 else max(1, round(BARW * dist[v] / n))
        w = max(0, min(w, BARW - used))
        used += w
        segs.append(_c("\u2588" * w, col, no_color))
    print("  " + "".join(segs))
    chips = []
    for v in present:
        col, icon = _VERDICT_STYLE.get(v, ("", "\u2022"))
        chips.append(_c(f"{icon} {dist[v]} {v}", col, no_color))
    print("  " + _c("   \u00b7   ", DIM, no_color).join(chips))
    print()

    # ---- GROUPED status list (coloured header; sections span full width) --------
    HC = CYAN_B + BOLD
    print("  " + _c(f"{'#':>{num_w}}", HC, no_color) + "   "
          + _cell("VERDICT", 16, HC, no_color) + "  "
          + _cell("MODULE", name_w, HC, no_color) + "  "
          + _cell("PORTS", port_w, HC, no_color) + "  "
          + _cell("MITRE", mitre_w, HC, no_color) + "  "
          + _cell("CWE", cwe_w, HC, no_color) + "  "
          + _cell("TIME", 8, HC, no_color) + "  "
          + _c("DETAIL", HC, no_color))

    idx = 0
    cur_cat = object()
    for d in rows:
        idx += 1
        if d["cat"] != cur_cat:
            cur_cat = d["cat"]
            lab = " " + (cur_cat or "Uncategorised") + " "
            fill = max(2, content_w - 5 - len(lab))      # span the FULL content width
            print("  " + _c("\u2576\u2500", ACC, no_color) + _c(lab, CYAN_B + BOLD, no_color)
                  + _c("\u2500" * fill + "\u2574", DIM, no_color))
        col, icon = _VERDICT_STYLE.get(d["v"], ("", "\u2022"))
        num = _c(f"{idx:>{num_w}}", DIM, no_color)
        gutter = _c("\u2590", col, no_color)
        print("  " + num + " " + gutter + " "
              + _cell(f"{icon} {d['v']}", 16, col, no_color) + "  "
              + _cell(d["name"], name_w, BOLD, no_color) + "  "
              + _cell((d.get("ports") or "\u2014"), port_w, DIM, no_color) + "  "
              + _cell((d.get("mitre") or "\u2014"), mitre_w, DIM, no_color) + "  "
              + _cell((d.get("cwe") or "\u2014"), cwe_w, DIM, no_color) + "  "
              + _cell(_hhmmss(d.get("ts")), 8, DIM, no_color) + "  "
              + _c(d["_detail"], DIM, no_color)
              + (_c(f"  {d.get('dur', 0.0):.1f}s", DIM, no_color) if debug else ""))
    print()

    findings = dist.get("SUCCESS", 0)
    detected = dist.get("DETECTED", 0)
    blocked = dist.get("BLOCKED", 0)
    print()
    print(_c(f"  → {findings} finding(s) got through"
             + (f", {detected} detected" if detected else "")
             + f"; {blocked} blocked.", BOLD, no_color))

    # Contamination banner: SUSPECT (BLOCKED that may be a source-IP ban) and
    # INCONCLUSIVE (never tested; source in IPS quarantine) are NOT control wins.
    # Call them out so a poisoned run isn't mistaken for a clean one.
    recs = getattr(ev, "records", []) or []
    inc_mods = sorted({r.get("attack", "?") for r in recs
                       if r.get("baseline_result") == "INCONCLUSIVE"})
    # a quarantine-stranded INCONCLUSIVE now also carries a SUSPECT tag (v1.9.18) —
    # list it under INCONCLUSIVE only, never also under the BLOCKED-suspect line.
    susp_mods = sorted({r.get("attack", "?") for r in recs
                        if "SUSPECT" in (r.get("verdict") or "")
                        and r.get("baseline_result") != "INCONCLUSIVE"})
    if inc_mods or susp_mods:
        warn = "\033[35m" if not no_color else ""
        rst = _RESET if not no_color else ""
        print(f"{warn}  ⚠ CONTAMINATED — re-run clean (whitelist the tester source / wait "
              f"out the IPS quarantine):{rst}")
        if inc_mods:
            print(f"{warn}      INCONCLUSIVE (not tested): {', '.join(inc_mods)}{rst}")
        if susp_mods:
            print(f"{warn}      SUSPECT (BLOCKED may be the ban): {', '.join(susp_mods)}{rst}")
        root = getattr(ev, "root", "")
        if root:
            print(f"{warn}      → python3 cli.py --suspect {root}{rst}")


def _parse_ports(spec):
    out = {}
    for part in (spec or "").replace(";", ",").split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            if v.strip().isdigit():
                out[k.strip()] = int(v.strip())
    return out


def _list_suspect(evidence_dir):
    """List modules a source-blacklist contaminated in a past run — both BLOCKEDs
    flagged SUSPECT and attacks recorded INCONCLUSIVE (not tested because the
    source was in IPS quarantine) — and print the command to re-run just those
    (after whitelisting the tester source on the appliance)."""
    import json
    path = os.path.join(evidence_dir, "summary.json") if os.path.isdir(evidence_dir) else evidence_dir
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] could not read {path}: {e}", file=sys.stderr)
        return 2
    susp = {}
    for r in data.get("results", []):
        # SUSPECT = a BLOCKED that may be the ban; INCONCLUSIVE = never tested
        # because the source was already quarantined. Both need re-running clean.
        if "SUSPECT" in (r.get("verdict") or "") or r.get("baseline_result") == "INCONCLUSIVE":
            susp.setdefault(r.get("target_ip", ""), set()).add(r.get("attack_id"))
    if not susp:
        print("No SUSPECT / INCONCLUSIVE (blacklist-contaminated) verdicts in that run — nothing to re-run.")
        return 0
    print("Blacklist-contaminated modules (BLOCKED may be the ban; INCONCLUSIVE = not tested):\n")
    for tgt, ids in susp.items():
        idlist = ",".join(sorted(i for i in ids if i))
        print(f"  Target {tgt}: {len(ids)} suspect module(s).")
        print("  After whitelisting the tester source on the appliance, re-run just these:")
        print(f"    python3 cli.py --target {tgt} --only {idlist} --confirm-roe\n")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Headless control-validation harness runner.")
    ap.add_argument("--version", action="version",
                    version=f"control-validation harness v{core.VERSION}")
    ap.add_argument("-t", "--target", default="127.0.0.1",
                    help="target IP/host; comma-separate for several in one scan, e.g. "
                         "the on-prem DC + the cloud DC: --target 192.168.122.209,159.223.35.108 "
                         "(each uses its own remembered cloud/creds). Default: 127.0.0.1")
    ap.add_argument("-i", "--iterations", type=int, default=1)
    ap.add_argument("-w", "--workers", type=int, default=core.RECOMMENDED_WORKERS)
    ap.add_argument("--mode", choices=["blackbox", "whitebox", "auto"], default=None,
                    help="assessment posture for the target(s): blackbox (through the SD-WAN "
                         "as-is — the default) or whitebox (allow-all baseline confirming the "
                         "attacks/services work), or 'auto' = use each target's DESIGNATED "
                         "posture from memory. Remembered PER TARGET (recalled when omitted)")
    ap.add_argument("--set-posture", choices=["blackbox", "whitebox"], default=None,
                    help="DESIGNATE the posture for --target (comma list) and exit WITHOUT "
                         "running — e.g. `--target 159.223.35.108 --set-posture whitebox`. "
                         "Every front-end then tests that IP in that posture by default.")
    ap.add_argument("-s", "--site-id", "--site", dest="site_id", default=None,
                    help="engagement/site tag recorded in the evidence + headers "
                         "(remembered per target; or set HARNESS_SITE_ID)")
    ap.add_argument("--debug", action="store_true",
                    help="verbose: ask tools for their own debug trace (curl -v / "
                         "ldapsearch -v / hydra -d / impacket -debug), stream each "
                         "module's full raw output live, and show per-module timing")
    ap.add_argument("--no-recon", action="store_true", help="skip the reachability recon")
    ap.add_argument("--cooldown", type=float, default=None,
                    help="seconds to wait before each brute/DoS (run_last) module so a "
                         "triggered rate-limit clears (also HARNESS_COOLDOWN)")
    ap.add_argument("--wait-unblock", type=float, default=None, metavar="SECONDS",
                    help="how long to wait for an IPS quarantine / source blacklist to "
                         "clear before marking the rest INCONCLUSIVE (re-probes the canary "
                         "every 5s). Default max(30s, cooldown); also HARNESS_WAIT_UNBLOCK")
    ap.add_argument("--ban-expiry", type=float, default=None, metavar="SECONDS",
                    help="known auto-expiry of the appliance's source-blacklist/quarantine "
                         "(the Sangfor 'Lockout Duration' — 300s on the lab). The wait-unblock "
                         "window is sized to outlast this. 0 = keep the old 30s window; also "
                         "HARNESS_BAN_EXPIRY")
    ap.add_argument("--auto-retry", type=int, default=None, metavar="N",
                    help="after an iteration, re-run attacks whose verdict was poisoned by a "
                         "source-blacklist (SUSPECT/INCONCLUSIVE/NO-SERVICE while banned), once "
                         "the ban clears, so they earn a real verdict. N rounds; 0 = off; "
                         "default 1. Also HARNESS_AUTO_RETRY")
    ap.add_argument("--bootstrap", action="store_true",
                    help="first install/update the APT tools the modules PREFER "
                         "(runs bootstrap.py, then continues with the run); pair with "
                         "--active to also install active-establishment tooling. Needs "
                         "apt + sudo/root. Optional — modules have Python fallbacks. For "
                         "bootstrap-only, run: python3 bootstrap.py")
    ap.add_argument("--force", action="store_true",
                    help="run modules even if prerequisites are missing (default: skip)")
    ap.add_argument("--require-root", action="store_true",
                    help="refuse to run unless privileged (root, OR passwordless/cached sudo "
                         "so the raw-socket modules can self-elevate). Opt-in: most modules "
                         "do NOT need root, so this is off by default.")
    ap.add_argument("--port", help='per-attack port overrides, e.g. "log4shell=8983,ssh_brute=2222"')
    sel = ap.add_mutually_exclusive_group()
    sel.add_argument("--only", help="comma list of module ids")
    sel.add_argument("--original", action="store_true",
                     help="only the initial 10-module baseline set (THIS IS THE DEFAULT)")
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
    ap.add_argument("--appliance", default=None, metavar="IP",
                    help="DUAL-PATH mode: also run each attack THROUGH this appliance "
                         "IP/path and compare. --target is the direct (allow-all) baseline "
                         "that proves the attack works; --appliance is the controlled path. "
                         "Verdicts: baseline OK + appliance BLOCKED = control works; "
                         "baseline OK + appliance SUCCESS = finding. Omit for single-target.")
    ap.add_argument("--cloud", dest="cloud", action="store_const", const=True, default=None,
                    help="cloud target: SMB/RPC are on alternate ports (default 445->4445, "
                         "135->1135). Maps them for the AD modules AND the recon. If omitted, "
                         "the last --cloud/--source used for this target is recalled.")
    ap.add_argument("--no-cloud", dest="cloud", action="store_const", const=False,
                    help="force cloud mode OFF (ignore any remembered --cloud for this target)")
    ap.add_argument("--smb-port", type=int, default=None, help="cloud SMB alt port (default 4445)")
    ap.add_argument("--rpc-port", type=int, default=None, help="cloud RPC alt port (default 1135)")
    ap.add_argument("--ssh-port", type=int, default=None, help="SSH port for ssh_brute (default 22; set a NAT alt here, e.g. 2222)")
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
    ap.add_argument("--suspect", metavar="EVIDENCE_DIR",
                    help="read a past run's summary.json and list the modules whose BLOCKED was "
                         "flagged SUSPECT (source-blacklist contamination), with a ready-to-paste "
                         "re-run command (do this after whitelisting the tester source)")
    ap.add_argument("--confirm-roe", action="store_true",
                    help="confirm rules-of-engagement for THIS run (or set it once with "
                         "--accept-roe / HARNESS_CONFIRM_ROE=1 and never pass it again)")
    ap.add_argument("--accept-roe", action="store_true",
                    help="record a DURABLE rules-of-engagement opt-in (.roe_accepted) so no "
                         "run needs --confirm-roe again, then exit")
    ap.add_argument("--evidence-dir", default="evidence")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--full-report", action="store_true",
                    help="also print the full ATT&CK/CWE/CVE report.txt to the console "
                         "(it is always written to the evidence dir regardless)")
    args = ap.parse_args()

    # Refuse to run an OUTDATED copy (confirmed outdated -> hard stop; offline ->
    # warn+run unless HARNESS_REQUIRE_LATEST; HARNESS_SKIP_VERSION_CHECK=1 bypasses).
    core.enforce_latest_version()

    if args.accept_roe:
        p = core.accept_roe()
        print(f"[roe] durable rules-of-engagement opt-in recorded ({p}). Runs no longer need "
              "--confirm-roe. Remove that file (or this is per-repo) to require it again."
              if p else "[!] could not write the ROE opt-in file", file=sys.stderr if not p else sys.stdout)
        return 0 if p else 2

    if args.bootstrap:
        import bootstrap as _bootstrap
        print(_c("\n[bootstrap] installing/updating the modules' preferred tooling "
                 "(--bootstrap)\u2026", ACC, args.no_color))
        try:
            _bootstrap.main(with_active=args.active)
        except SystemExit as e:
            if e.code:
                print(_c(f"[bootstrap] finished with warnings (exit {e.code}) \u2014 some "
                         "packages may be missing; modules will use their Python fallbacks. "
                         "Continuing with the run.", AMBER, args.no_color), file=sys.stderr)
        except Exception as e:
            print(_c(f"[bootstrap] error: {e} \u2014 continuing (modules have Python "
                     "fallbacks).", AMBER, args.no_color), file=sys.stderr)

    modules = loader.discover()

    if args.suspect:
        return _list_suspect(args.suspect)

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

    # Designate-only: pin each target's posture to memory and exit — no attacks,
    # so no ROE gate. Every front-end (CLI auto-recall, web "Auto", fleet auto)
    # then tests that IP in the designated posture by default.
    if args.set_posture:
        tgts = [t.strip() for t in (args.target or "").split(",") if t.strip()]
        if not tgts:
            print("[!] --set-posture needs --target <ip[,ip...]>", file=sys.stderr)
            return 2
        for t in tgts:
            ok, why = core.validate_target(t)
            if not ok:
                print(f"[!] {t}: {why}", file=sys.stderr)
                return 2
        # co-designate TRANSPORT when --cloud/--no-cloud (and optional ports) are
        # given, so one command pins the whole profile — e.g. an on-prem DC:
        #   --target 10.38.98.12 --set-posture whitebox --no-cloud   (direct 445/135)
        # A wrong cloud flag is exactly what makes SMB modules (dcsync/psexec/…)
        # hit a closed NAT port and read as NO-SERVICE instead of connecting.
        extra = {}
        if args.cloud is not None:
            extra["cloud"] = bool(args.cloud)
            if args.cloud:
                extra["smb_port"] = args.smb_port or 4445
                extra["rpc_port"] = args.rpc_port or 1135
                extra["ssh_port"] = args.ssh_port or 22
        for t in tgts:
            core.remember_target(t, mode=args.set_posture, **extra)
            xp = ""
            if "cloud" in extra:
                xp = " · " + (f"cloud {extra['smb_port']}/{extra['rpc_port']}" if extra["cloud"] else "on-prem direct")
            print(f"[posture] {t} -> {args.set_posture}{xp} (designated; no attack run)")
        return 0

    target_defaulted = not any(
        a in ("-t", "--target") or a.startswith(("--target=", "-t"))
        for a in sys.argv)
    if target_defaulted:
        print(f"[default] no --target given → using {args.target} (the local lab). "
              "Pass --target <ip> for a remote target.")
    if not (args.confirm_roe or core.roe_accepted()):
        print("[!] refusing to run without rules-of-engagement confirmation (this tool runs "
              "REAL attacks). Confirm ONCE and you won't need the flag again:\n"
              "    python3 cli.py --accept-roe          # durable opt-in (writes .roe_accepted)\n"
              "  or set HARNESS_CONFIRM_ROE=1 in your env, or pass --confirm-roe per run.",
              file=sys.stderr)
        return 2

    selected = _select(modules, args)
    if not selected:
        print("[!] no modules selected", file=sys.stderr)
        return 2

    # Opt-in privilege gate (--require-root): refuse unless we can actually elevate the
    # raw-socket modules. NOT the default — most modules need no root. Accepts
    # passwordless/cached sudo (the modules self-elevate via `sudo -n`), not just root.
    if args.require_root:
        ps = core.privilege_status(selected)
        if not (ps["root"] or ps["sudo_nopasswd"]):
            print("[!] --require-root set but not privileged: " + ps["how"] + ".\n"
                  "    Fix: run as root, `sudo -v` to cache a ticket, or setcap hping3 "
                  "(python3 bootstrap.py). Omit --require-root to run the non-root modules anyway.",
                  file=sys.stderr)
            return 2

    # Clean live rendering: the engine's own per-module log lines interleave
    # under concurrency; suppress those on the console (they stay in the
    # evidence run.log) and re-render each result as a tidy numbered line via
    # on_status. The banner / preflight / recon / health setup output is kept.
    _cats = {m.META.get("category", "") for m in selected}
    _iters = max(1, args.iterations)

    def _run_one_target(target, label=None, mods=None):
        """Prepare + run the selected modules against ONE target, applying that
        target's own recalled source/cloud/creds/site. Returns (root, exit_code).
        Called once per --target so a single scan can hit A->B (kvdc, direct
        ports/creds) AND A->C (cloud DO, NAT'd ports/creds) — each target pulls
        its OWN remembered config, so the two don't clash."""
        run_set = mods if mods is not None else selected
        _total = len(run_set) * _iters
        _prog = {"n": 0}
        _setup = {"buf": [], "done": False}   # collect the setup log -> one tidy panel

        def _on_log(m):
            s = str(m)
            if args.debug:                  # debug: keep the full engine stream
                print(_colorize(s, args.no_color)); return
            st = s.strip()
            if st.lower().startswith(("target:", "baseline:")):
                return  # per-module verdict line — re-rendered by on_status
            # the engine's plain "===" banner (Harness v / MODE / SITE ID) is
            # re-rendered as a modern CLI banner before the run; drop it from the
            # console (still written to the evidence run.log).
            if st == "=" * 60 or st.startswith(("Harness v", "MODE:", "SITE ID:")):
                return
            for c in _cats:                 # "  [Category] Name" now-running line
                if c and st.startswith(f"[{c}]"):
                    return
            # Buffer the one-time setup block (platform/preflight/recon/policy) and
            # render it as a single labelled 'command-center' panel at run start,
            # instead of a wall of flat lines.
            if not _setup["done"]:
                if st.startswith("=== Iteration"):
                    _setup["done"] = True
                    _setup_panel(_setup["buf"], args, (len(run_set), _iters, args.workers))
                    print()
                    return   # the plain "=== Iteration: 1 ===" rule is folded into the panel
                _setup["buf"].append(st)
                return
            # tidy the two run-start lines into the RUN panel's kv style (the long
            # deferred name-list is dropped here — those modules appear in the live list).
            import re as _re3
            _md = _re3.match(r"deferred last \(ban-safe\):\s*(\d+)", st)
            if _md:
                print("     " + _c(f"{'deferred':<11}", DIM, args.no_color) + " "
                      + _c(f"{_md.group(1)} module(s) run LAST (ban-safe — contamination guard)",
                           DIM, args.no_color))
                return
            _mr = _re3.match(r"running (\d+) module\(s\) with (\d+) workers", st)
            if _mr:
                print("     " + _c(f"{'parallel':<11}", DIM, args.no_color) + " "
                      + _c(f"{_mr.group(1)} module(s) · {_mr.group(2)} workers", DIM, args.no_color))
                print()
                return
            print(_colorize(s, args.no_color))

        def _on_output(aid, name, it, raw):
            if not args.debug:
                return
            print(_c(f"\n──── {name} — raw output ────", DIM, args.no_color))
            print(str(raw).rstrip())

        def _on_status(aid, name, it, b, v):
            _prog["n"] += 1
            nn, tot = _prog["n"], _total
            col, icon = _VERDICT_STYLE.get(b, ("", "•"))
            # realtime progress: a bar that grows as modules complete, + % + clock
            pct = int(100 * nn / tot) if tot else 100
            bw = 12
            fill = max(0, min(bw, int(round(bw * nn / tot)))) if tot else bw
            bar = _c("█" * fill, ACC, args.no_color) + _c("░" * (bw - fill), DIM, args.no_color)
            counter = _c(f"{nn:>3}/{tot}", DIM, args.no_color)
            clock = _c(time.strftime("%H:%M:%S"), DIM, args.no_color)
            # pad the PLAIN label (widest verdict is NOT-VULNERABLE = 14) so the module
            # name column stays aligned regardless of verdict length, THEN colour it.
            verd = _c(f"{icon} {b:<14}", col, args.no_color)
            print(f"  {counter} ▕{bar}▏{_c(f'{pct:>3}%', BOLD, args.no_color)} {clock}  {verd} {name}")

        runner = core.Runner(target, args.appliance or None, on_log=_on_log,
                             on_output=_on_output, on_status=_on_status)
        runner.concurrency = max(1, args.workers)
        if args.cooldown is not None:
            runner.cooldown = max(0.0, args.cooldown)
        if args.wait_unblock is not None:
            runner.wait_unblock = max(0.0, args.wait_unblock)
        if args.ban_expiry is not None:
            runner.ban_expiry = max(0.0, args.ban_expiry)
        if args.auto_retry is not None:
            runner.auto_retry = max(0, args.auto_retry)
        runner.ctx.debug = bool(args.debug)
        overrides = _parse_ports(args.port)
        if overrides:
            runner.ctx.port_overrides = overrides
        runner.ctx.allow_active = bool(args.active)

        # Per-target memory: recall this target's source/cloud options when the
        # flag was omitted, then persist whatever we end up using.
        mem = core.recall_target(target)
        source = args.source if args.source is not None else mem.get("source")
        # Transport is TARGET-authoritative: a canonical cloud DC (159/167) is ALWAYS
        # NAT'd 4445/1135 (so dcsync/psexec/wmiexec can't be pointed at the dead raw
        # 445/135 and wrongly score BLOCKED); everything else is on-prem 445/135
        # unless explicitly forced cloud. --cloud/--no-cloud/memory only matter for a
        # NON-canonical target.
        cloud = core.is_cloud_target(target) or (
            args.cloud if args.cloud is not None else bool(mem.get("cloud")))
        # posture (whitebox/blackbox) is per-target: an explicit flag wins, else
        # ('auto'/omitted) the target's DESIGNATED posture from memory, else blackbox.
        mode = core.resolve_posture(target, args.mode)
        if (args.mode in (None, "auto")) and mem.get("mode") and args.debug:
            # redundant with the panel header (which shows posture) — debug-only
            print(f"[recall] posture {mode} (designated for {target})")
        ssh_p_port = args.ssh_port or (mem.get("ssh_port") if cloud else None) or 22
        if source:
            runner.ctx.source_ip = source
            if args.source is None and args.debug:   # now in the banner CREDS row
                print(f"[recall] source {source} (remembered for {target})")
        # Register (or clear) the NAT map target-authoritatively (canonical cloud is
        # never cleared; non-cloud never gets 4445/1135 unless forced).
        eff_cloud, eff_map = core.apply_transport(target, cloud, ssh_p_port)
        cloud = eff_cloud
        smb = (eff_map or {}).get(445, 4445)
        rpc = (eff_map or {}).get(135, 1135)
        if eff_map:
            tag = " (canonical cloud)" if core.is_cloud_target(target) else (
                "" if args.cloud is not None else " (recalled)")
            if args.debug:   # transport now shown in the banner TARGET row
                print(f"[cloud{tag}] {target}: SMB 445->{smb}, RPC 135->{rpc}, SSH 22->{eff_map.get(22, 22)}")

        # Apply an explicit --ssh-port even WITHOUT --cloud: a direct Linux target
        # may run SSH on a non-standard port. Feed it to ssh_brute via
        # port_overrides so the hydra subprocess actually targets it (previously
        # --ssh-port was silently ignored unless --cloud was also set). Cloud mode
        # already NATs 22->ssh via _portpatch above; an explicit
        # `--port ssh_brute=N` still wins (setdefault).
        if args.ssh_port and not cloud:
            try:
                po = dict(getattr(runner.ctx, "port_overrides", None) or {})
                po.setdefault("ssh_brute", int(args.ssh_port))
                runner.ctx.port_overrides = po
                print(f"[ssh] ssh_brute -> port {args.ssh_port} (direct target)")
            except (TypeError, ValueError):
                print(f"[!] bad --ssh-port {args.ssh_port!r}", file=sys.stderr)

        # Per-target CREDENTIALS (DC + separate SSH) — flag > remembered.
        dom = args.domain or mem.get("domain")
        usr = args.dc_user or mem.get("dc_user")
        pw = args.dc_pass if args.dc_pass is not None else mem.get("dc_pass")
        if dom:
            runner.ctx.creds["domain"] = dom
        if usr:
            runner.ctx.creds["dc_user"] = usr
        if pw is not None:
            runner.ctx.creds["dc_pass"] = pw
        if ((dom or usr or pw is not None) and not (args.domain or args.dc_user or args.dc_pass is not None)
                and args.debug):   # now in the banner CREDS row
            print(f"[recall] creds for {target}: {runner.ctx.creds.get('domain')}/"
                  f"{runner.ctx.creds.get('dc_user')} (remembered)")
        ssh_u = args.ssh_user or mem.get("ssh_user")
        ssh_p = args.ssh_pass if args.ssh_pass is not None else mem.get("ssh_pass")
        if ssh_u:
            runner.ctx.creds["ssh_user"] = ssh_u
        if ssh_p is not None:
            runner.ctx.creds["ssh_pass"] = ssh_p
        site_id = args.site_id or mem.get("site_id") or ""
        if site_id and not args.site_id and args.debug:
            # redundant with the panel header (which shows the site) — debug-only
            print(f"[recall] site {site_id} (remembered for {target})")
        # remember creds/site only when explicitly given this run.
        cred_fields = {}
        if args.domain is not None: cred_fields["domain"] = args.domain
        if args.dc_user is not None: cred_fields["dc_user"] = args.dc_user
        if args.dc_pass is not None: cred_fields["dc_pass"] = args.dc_pass
        if args.ssh_user is not None: cred_fields["ssh_user"] = args.ssh_user
        if args.ssh_pass is not None: cred_fields["ssh_pass"] = args.ssh_pass
        if args.site_id is not None: cred_fields["site_id"] = args.site_id
        if args.mode in ("blackbox", "whitebox"): cred_fields["mode"] = args.mode
        core.remember_target(target, source=source or None, cloud=bool(cloud),
                             smb_port=(smb if cloud else None), rpc_port=(rpc if cloud else None),
                             ssh_port=(ssh_p_port if (cloud or args.ssh_port) else None),
                             **cred_fields)

        # ---- modern CLI banner (the engine's plain === banner is suppressed on
        # the console by _on_log and kept in the evidence run.log) ----
        _net = "cloud" if cloud else "on-prem"
        _dest = f"{source} → {target}" if source else str(target)
        _wb = str(mode).lower().startswith("w")
        _modeline = ("● WHITEBOX — allow-all baseline (attacks SHOULD pass)"
                     if _wb else "● BLACKBOX — through the SD-WAN (what the boundary stops)")
        # flat header (no heavy box) — the logo, a bold posture line, then a
        # "MISSION" section whose dividers + kv style match the panels and results.
        def _sec(label):
            lab = " " + label + " "
            print("  " + _c("╶─", ACC, args.no_color) + _c(lab, CYAN_B + BOLD, args.no_color)
                  + _c("─" * max(2, 72 - len(lab) - 2) + "╴", DIM, args.no_color))

        def _kv(k, v, vcol=DIM):
            print("     " + _c(f"{k:<11}", DIM, args.no_color) + " " + _c(str(v), vcol, args.no_color))

        _print_logo(args.no_color)
        print()
        print("  " + _c(_modeline, (CYAN_B + BOLD) if _wb else (AMBER + BOLD), args.no_color))
        _sec("MISSION")
        _kv("target", f"{target}   ·   {_net}" + (f"   ·   site {site_id}" if site_id else ""), CYAN_B)
        if cloud and eff_map:
            _kv("transport", "SMB 445→%s · RPC 135→%s · SSH 22→%s"
                % (smb, rpc, eff_map.get(22, 22)))
        else:
            _kv("transport", "direct SMB 445 · RPC 135 · SSH %s" % ssh_p_port)
        # real source/egress IP (where this run leaves from). Explicit --source wins;
        # otherwise detect the egress IP (display only, does NOT force a bind). Exposed as
        # ctx.display_source so the evidence + RESULTS header are self-describing too.
        _egress = source or _egress_ip(target)
        runner.ctx.display_source = _egress or ""
        _src_disp = source if source else (f"{_egress} (auto)" if _egress else "unknown route")
        _kv("source", "%s  →  %s" % (_src_disp, target))
        _cred_id = ("%s\\%s" % (runner.ctx.creds.get("domain") or "",
                                runner.ctx.creds.get("dc_user") or "")).strip("\\")
        _kv("creds", _cred_id or "(none set)")

        t0 = time.time()
        try:
            ev = core.Evidence(base=args.evidence_dir, label=label)
            root = runner.run(run_set, _iters, ev, skip_unready=not args.force,
                              recon=not args.no_recon, mode=mode, site_id=site_id or None)
        except ValueError as e:               # invalid target / allowlist refusal
            print(f"[!] {e}", file=sys.stderr)
            return None, 2
        except KeyboardInterrupt:
            print("\n[!] interrupted", file=sys.stderr)
            return None, 130
        try:
            _print_summary(ev, args, args.no_color, time.time() - t0, target=target)
        except Exception as e:
            print(f"[!] summary error (non-fatal): {e}", file=sys.stderr)
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
        return root, 0

    # One scan, one or more targets (comma-separated): e.g. the on-prem DC (B) and
    # the cloud DC (C) in a single invocation. Each runs with its OWN recalled config.
    targets = [t.strip() for t in (args.target or "").split(",") if t.strip()] or [args.target]
    multi = len(targets) > 1
    worst, roots = 0, []
    for i, tgt in enumerate(targets, 1):
        # egress/target-independent modules run ONCE (on the first target); later
        # targets run only the target-dependent set, so the same egress test isn't
        # repeated per target (where only Kali's egress state would differ).
        mods = selected if i == 1 else [m for m in selected if not _is_egress(m)]
        if multi:
            print(_c(f"\n{'═' * 64}", ACC, args.no_color))
            print(_c(f" TARGET {i}/{len(targets)}:  {tgt}", "\033[1m", args.no_color))
            print(_c(f"{'═' * 64}", ACC, args.no_color))
            dropped = len(selected) - len(mods)
            if dropped:
                print(_c(f"  ({dropped} egress/target-independent module(s) already run "
                         f"against {targets[0]} — not repeated here)", DIM, args.no_color))
        root, rc = _run_one_target(tgt, label=(tgt if multi else None), mods=mods)
        worst = max(worst, rc)
        if root:
            roots.append((tgt, root))
    if multi:
        print(_c(f"\n  Scanned {len(targets)} targets:", "\033[1m", args.no_color))
        for tgt, root in roots:
            print(_c(f"    {tgt}  →  {root}", ACC, args.no_color))
    return worst


if __name__ == "__main__":
    sys.exit(main())
