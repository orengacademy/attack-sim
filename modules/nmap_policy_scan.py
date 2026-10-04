"""NMAP Port-Policy Violation Scan (IPS-bypass).

Scans the target's TCP (default 1-65535) and top UDP ports and reports every OPEN
port that VIOLATES the boundary port policy (Polisi Standard Security v1.3 by
default) — i.e. a reachable service the policy does NOT permit. That is the real
question behind the allow-list: "what is exposed beyond the common ports allowed?"

The SD-WAN runs a port-scan IPS, so a naive full scan trips it and the source gets
blacklisted. This module evades it with the classic firewall/IPS bypasses:
  * --source-port <allowed>  (-g): scan packets carry an ALLOWED service source
    port (e.g. 443), so stateless port-scan detectors see them as replies from a
    permitted service rather than a scan.
  * -f (fragment) + slow timing (-T2/-T3): dodge reassembly-light and rate-based
    port-scan signatures.
  * -Pn -n: no ping / no DNS (the boundary often drops ICMP, which would make a
    pinging scan wrongly think the host is down).

Needs root (SYN/UDP/fragment/source-port) and nmap; PREREQ-MISSING otherwise.
serial + run_last + trips_ips: a full scan reliably trips the port-scan IPS and
blacklists the source, so it runs LAST so it can't contaminate other modules.

Verdicts:
  * POLICY-VIOLATION  -> open ports outside the allow-list were found AND the scan
    got through the IPS (finding).
  * SCAN-BLOCKED      -> no results / host fully filtered: the port-scan IPS most
    likely blocked/blacklisted the source (the control worked).
  * POLICY-ENFORCED   -> the scan got through but only allowed services are open
    (no violation — the allow-list is enforced).

Env knobs: HARNESS_SCAN_TCP_PORTS (default "1-65535"), HARNESS_SCAN_TIMING
(default "-T3"; use "-T1"/"-T2" for stealthier), HARNESS_SCAN_SRCPORT (override
the bypass source port).

TIME-SPREAD STEALTH MODE (HARNESS_SCAN_STEALTH=1): splits the TCP range into
batches scanned slowly (-T1 + --scan-delay) with the source-port/fragment bypass
and a pause between batches, so the per-time probe rate stays UNDER a rate-based
port-scan IPS threshold — the realistic way to evade a modern NGFW's scan
detection. Tunables: HARNESS_SCAN_BATCHES (default 8), HARNESS_SCAN_BATCH_DELAY
seconds (default 20), HARNESS_SCAN_DELAY_MS per-probe (default "50ms"),
HARNESS_SCAN_BUDGET total wall-clock seconds (default 1800; keep under ~3000 so
it finishes within the module's 3600s watchdog).
"""
import os
import re
import shlex
import time

META = {
    "id": "nmap_policy_scan",
    "name": "NMAP Port-Policy Violation Scan (IPS-bypass)",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "added": True,
    "control": "Allowed-port policy enforcement + port-scan IPS (App-ID / NGFW)",
    "fix": "SD-WAN",
    "mitre": ['T1046', 'T1595.001'],
    "cwe": ['CWE-923'],
    "tactic": 'Discovery',
    "requires": ["nmap"],
    "needs_root": True,          # -sS / -sU / -f / -g need raw sockets
    "os_supported": ["Linux"],
    "serial": True,
    "run_last": True,            # trips the port-scan IPS / blacklists the source
    "trips_ips": True,
    # stealth mode deliberately runs for many minutes (time-spread batches), so
    # the module declares its own longer watchdog (engine honours hard_timeout_s).
    "hard_timeout_s": 3600,
    "ports": [],                 # performs its own scan; recon would duplicate it
    "success_regex": r"^POLICY-VIOLATION",
    "blocked_regex": r"^SCAN-BLOCKED|^POLICY-ENFORCED|No route|Network is unreachable",
}

# grepable nmap: "Ports: 22/open/tcp//ssh///, 3389/open/tcp//ms-wbt-server///"
_PORT_RE = re.compile(r"(\d+)/open/(tcp|udp)/")


def _bypass_srcport(pol):
    """Pick an ALLOWED tcp source port so scan packets look like replies from a
    permitted service (preference order; falls back to 53)."""
    env = (os.environ.get("HARNESS_SCAN_SRCPORT") or "").strip()
    if env.isdigit():
        return int(env)
    allow = pol["allow"]["tcp"]
    for p in (443, 53, 88, 80, 123):
        if p in allow:
            return p
    return 53


def _scan(ctx, target, argv_template):
    """Run one nmap invocation via ctx.run_cmd (shlex-split, no shell), return the
    raw output. Open (proto,port) tuples are parsed from the grepable -oG output."""
    return ctx.run_cmd(argv_template, target)


def _split_range(spec, n):
    """Split a 'lo-hi' port range into n contiguous sub-ranges for time-spread
    batching. A non-range spec (comma list etc.) is scanned as a single batch."""
    m = re.match(r"^(\d+)-(\d+)$", spec)
    if not m or n <= 1:
        return [spec]
    lo, hi = int(m.group(1)), int(m.group(2))
    if hi <= lo:
        return [spec]
    size = (hi - lo + 1 + n - 1) // n
    out, p = [], lo
    while p <= hi:
        q = min(p + size - 1, hi)
        out.append(f"{p}-{q}")
        p = q + 1
    return out


def run(target, ctx):
    import core   # imported here (not at top) to avoid any import-order surprise
    pol = core.load_port_policy()
    srcport = _bypass_srcport(pol)
    tcp_ports = (os.environ.get("HARNESS_SCAN_TCP_PORTS") or "1-65535").strip()
    timing = (os.environ.get("HARNESS_SCAN_TIMING") or "-T3").strip()
    if not re.match(r"^-T[0-5]$", timing):
        timing = "-T3"

    out = [f"# NMAP port-policy violation scan vs {target}",
           f"# policy: {pol['name']}  |  IPS-bypass: --source-port {srcport} (allowed), "
           f"-f (fragment), {timing}, -Pn -n"]

    stealth = (os.environ.get("HARNESS_SCAN_STEALTH", "").strip().lower()
               in ("1", "true", "yes", "on"))

    # ---- TCP ----------------------------------------------------------------
    if stealth:
        # TIME-SPREAD STEALTH: split the range into N batches, scan each slowly
        # (-T1 + --scan-delay) with the source-port/fragment bypass, and sleep
        # between batches so the per-time probe rate stays UNDER a rate-based
        # port-scan IPS threshold. Bounded by a total wall-clock budget.
        def _int(env, d):
            try:
                return max(1, int(float(os.environ.get(env) or d)))
            except ValueError:
                return d
        batches = max(2, _int("HARNESS_SCAN_BATCHES", 8))
        batch_delay = max(0, _int("HARNESS_SCAN_BATCH_DELAY", 20))
        budget = max(60, _int("HARNESS_SCAN_BUDGET", 1800))
        scan_delay = (os.environ.get("HARNESS_SCAN_DELAY_MS") or "50ms").strip()
        s_timing = timing if timing in ("-T0", "-T1") else "-T1"
        slices = _split_range(tcp_ports, batches)
        per_host = max(60, budget // max(1, len(slices)))
        out.append(f"\n## STEALTH TCP — {len(slices)} time-spread batch(es), {s_timing} "
                   f"--scan-delay {scan_delay}, {batch_delay}s between batches, "
                   f"budget {budget}s (stays under a rate-based scan IPS)")
        parts, t0 = [], time.time()
        for i, sl in enumerate(slices, 1):
            if time.time() - t0 > budget:
                out.append(f"[budget {budget}s reached — stopped after {i - 1}/{len(slices)} batches]")
                break
            tmpl = (f"nmap -sS -p {sl} {s_timing} --scan-delay {scan_delay} -g {srcport} -f "
                    f"--max-retries 1 --host-timeout {per_host}s --open -n -Pn -oG - {{target}}")
            out.append(f"\n# batch {i}/{len(slices)}: ports {sl}")
            raw = _scan(ctx, target, tmpl)
            out.append(raw); parts.append(raw)
            if i < len(slices) and (time.time() - t0) < budget and batch_delay:
                time.sleep(batch_delay)
        tcp_raw = "\n".join(parts)
    else:
        # fast single pass, bounded under the default watchdog.
        tcp_tmpl = (f"nmap -sS -p {shlex.quote(tcp_ports)} {timing} -g {srcport} -f "
                    f"--max-retries 1 --host-timeout 180s --open -n -Pn -oG - {{target}}")
        out.append(f"\n## TCP ({tcp_ports}, SYN, fragmented, src-port {srcport})")
        tcp_raw = _scan(ctx, target, tcp_tmpl)
        out.append(tcp_raw)

    # ---- UDP (one pass; slower in stealth) ----------------------------------
    udp_timing = "-T1" if stealth else timing
    udp_tmpl = (f"nmap -sU --top-ports 50 {udp_timing} -g {srcport} "
                f"--max-retries 1 --host-timeout 90s --open -n -Pn -oG - {{target}}")
    out.append("\n## UDP (top 50, src-port %d)" % srcport)
    udp_raw = _scan(ctx, target, udp_tmpl)
    out.append(udp_raw)

    combined = f"{tcp_raw}\n{udp_raw}"
    opens = sorted({(m.group(2), int(m.group(1))) for m in _PORT_RE.finditer(combined)})

    # did the scan reach the target at all?
    reached = bool(opens) or ("Status: Up" in combined) or ("/open/" in combined)
    scan_failed = ("failed to determine" in combined.lower()
                   or "0 hosts up" in combined.lower()
                   or ("Host: " not in combined and not opens))

    # classify each open port against the policy
    violations, allowed_open = [], []
    for proto, port in opens:
        st = core.port_policy_status(proto, port, pol)
        tag = f"{proto}/{port}"
        (allowed_open if st == "allowed" else violations).append((tag, st))

    out.append("")
    if opens:
        out.append("OPEN: " + ", ".join(f"{t}({s})" for t, s in sorted(allowed_open + violations)))

    if violations:
        vlist = ", ".join(t for t, _ in violations)
        out.append(
            f"POLICY-VIOLATION: {len(violations)} open port(s) violate {pol['name']} "
            f"(not in the allow-list): {vlist} — exposed services the boundary should "
            f"NOT permit. The scan also BYPASSED the port-scan IPS (results returned via "
            f"--source-port {srcport} / fragmentation). [FINDING] Close these or deny them "
            f"at the boundary; and tune the port-scan IPS to catch source-port-spoofed scans.")
    elif not reached or scan_failed:
        out.append(
            "SCAN-BLOCKED: nmap returned no open ports and the host appears filtered/down "
            "to the scan — the port-scan IPS most likely blocked or blacklisted the source "
            "(or the target is fully filtered). The source-port/fragmentation bypass did not "
            "get through. (Confirm against the appliance logs; a blacklist also shows up as a "
            "later-module SUSPECT/INCONCLUSIVE via the contamination guard.)")
    else:
        out.append(
            "POLICY-ENFORCED: the scan got through the IPS but only ALLOWED services are open "
            "— no policy-violating ports reachable (the allow-list is enforced at this target).")

    return "\n".join(out)
