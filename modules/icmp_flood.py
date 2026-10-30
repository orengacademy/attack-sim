"""ICMP Flood (DoS) — tests ICMP rate-limit / flood protection at the boundary.

The old model asked "did I DoS the target into packet loss?" — which needs a
volume a single host can't push over the internet, so it dead-ended at
"0% loss → inconclusive". Wrong question for a *boundary* control.

The right question an SD-WAN/segmentation control answers is "does the boundary
rate-limit or drop a high-rate ICMP flood?" — and THAT is measurable from one
host as a **differential**:

  1. baseline  — normal-rate ICMP (`ping -i 0.2`): does ordinary ICMP work at all?
  2. RAMP      — step high-rate ICMP UP through several rates (`hping3 -1`,
                 HARNESS_ICMP_RAMP pps x near-MTU payload) and find the KNEE: the
                 lowest rate where delivery drops / RTT inflates vs baseline.

Verdict (DECISIVE — a delivery collapse on a high-rate flood is the boundary):
  * any ramp step's delivery collapses (loss jumps >= RATE_LIMIT_DELTA over baseline, or
    RTT shaping) while ordinary pings work -> the boundary polices = BLOCKED
    (BLOCKED-DOS-DETECTED if ~total loss, else BLOCKED-RATELIMIT), with the MEASURED
    threshold reported. This reads BLOCKED even at a LOW volume (the field's 2,100-pps /
    ~24 Mbit/s DENY) and whether or not the source reached the full target rate — a single
    host doesn't saturate a remote target at these rates, so a drop is the boundary. Vendor
    anti-DoS thresholds (Sangfor NGAF / Forcepoint NGFW) aren't published, so we MEASURE.
  * every ramp step is delivered -> NO policing up to the most this source could
    push = SUCCESS/finding; the achieved ceiling is reported so a below-threshold
    PASS isn't mistaken for "no policing at any volume".
  * There is NO default INCONCLUSIVE for a loss knee. The ONLY opt-in exception: a
    thin-link tester DECLARES its uplink (HARNESS_ICMP_UPLINK_MBPS) and the loss appeared
    at/above that uplink's usable headroom -> the tester's OWN uplink saturated, not the
    target -> INCONCLUSIVE. A low-volume BLOCKED carries a caveat pointing to this knob.
  * the hping3 ramp produced NO parseable stats on any step (timed out / output wiped by a
    mid-send ban) -> fall through to the datagram fallback rather than a false PASS.
  * baseline ICMP 100% lost but the host is up on TCP -> ICMP filtered entirely =
    BLOCKED-ICMP-FILTERED; can't confirm the host is up -> INCONCLUSIVE (liveness only).
  * datagram FALLBACK: a near-TOTAL during-flood loss with a clean baseline -> BLOCKED
    (blackhole/DENY); otherwise delivered -> PASS (partial datagram reply-loss is the
    host kernel's ICMP-reply rate-limit, not attributable, so it is NOT scored BLOCKED).

This is decisive in BOTH environments: against a lab with no ICMP policing the
flood is delivered (SUCCESS/finding); against an SD-WAN that rate-limits ICMP the
high-rate stream is dropped while pings still work (BLOCKED). hping3 is the
primary engine (raw-socket line rate + a clean delivery-ratio in its stats); a
pure-Python fallback keeps the module runnable without it (best-effort — it can
confirm the flood had an effect but not fully characterise rate-limiting).

needs_root (raw sockets / CAP_NET_RAW). Run only inside an authorised window.
"""
import errno
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time

BASELINE_COUNT = 15        # normal-rate ICMP sample
BASELINE_INTERVAL = "0.2"  # seconds between baseline pings (5 pps)


def _int_env(name, default, lo=1):
    try:
        return max(lo, int(os.environ.get(name) or default))
    except (TypeError, ValueError):
        return default


def _frac_env(name, default, lo=0.0, hi=1.0):
    """Parse a 0..1 fraction from env, clamped; else the default."""
    try:
        return min(hi, max(lo, float(os.environ.get(name) or default)))
    except (TypeError, ValueError):
        return default


def _list_env(name, default):
    """Parse a comma-separated int list from env, else the default list."""
    v = os.environ.get(name)
    if not v:
        return list(default)
    try:
        return [int(x) for x in v.replace(" ", "").split(",") if x] or list(default)
    except ValueError:
        return list(default)


# High-rate flood params — ALL overridable so the operator / SD-WAN team can CRANK
# the aggression until the anti-DoS either DROPS the flood (BLOCKED = it prevents at
# that rate) or confirms it never drops (a finding: it only ALERTS). Defaults are
# ~20k pps x 1400B for 15s (host pushes ~168 Mbit/s) = a BANDWIDTH flood by default,
# since a bits/sec-based anti-DoS (like this lab's SD-WAN, ~84 Mbit/s ICMP ceiling)
# only ALERTS on a small-packet pps flood but DROPS a fat-packet one. This default was
# measured to cross the drop threshold (~51%% loss). Set HARNESS_ICMP_SIZE=0 for a pure pps test.
FLOOD_PPS = _int_env("HARNESS_ICMP_PPS", 20000)                        # target packets/sec
FLOOD_SECONDS = _int_env("HARNESS_ICMP_SECONDS", 15)                   # wall-clock cap (s)
FLOOD_COUNT = _int_env("HARNESS_ICMP_COUNT", FLOOD_PPS * FLOOD_SECONDS)  # total packets
FLOOD_SIZE = _int_env("HARNESS_ICMP_SIZE", 1400, lo=0)                 # ICMP payload bytes. Default 1400 (near-MTU) = a BANDWIDTH flood: this lab's SD-WAN (and many anti-DoS engines) threshold on BITS/sec, not pps, so a header-only flood only ALERTS while a fat-packet one gets DROPPED. Set 0 for a pure packet-rate test.
FLOOD_INTERVAL_US = max(1, 1_000_000 // FLOOD_PPS)                     # hping3 -i uX derived from pps
# Parallel senders for the pure-Python fallback (used when hping3's raw socket is
# unavailable, e.g. WSL1). A single Python send loop tops out ~1k pps; blasting one
# precomputed FLOOD_SIZE packet from N threads (sendto releases the GIL) pushes enough
# volume to actually exercise a bits/sec anti-DoS. Override with HARNESS_ICMP_FLOOD_WORKERS.
FLOOD_WORKERS = _int_env("HARNESS_ICMP_FLOOD_WORKERS", 16, lo=1)
LOW_LOSS = 20              # <= this %: that rate is "getting through"
RATE_LIMIT_DELTA = 30      # flood loss this many points ABOVE baseline => policed
# ATTRIBUTION: a loss knee is only a TARGET control if the source actually REACHED
# (close to) the rate it's blaming the target for. hping3 sends blind — its achieved
# pps reflects the SENDER's NIC/CPU/uplink ceiling, not the target. So if a knee
# appears at a step where achieved << target (the source couldn't even push the
# requested rate), the loss is the SOURCE saturating its own uplink (self-congestion),
# NOT the boundary policing — scoring that BLOCKED would credit a control that was
# never proven. Require achieved >= this fraction of target at the knee to call it a
# control; below it, report the flood as DELIVERED-to-source-ceiling (a finding).
SATURATION_FRAC = _frac_env("HARNESS_ICMP_SAT_FRAC", 0.80)
# THRESHOLD-AWARE verdict: a DELIVERED flood only proves "no policing" if it actually
# pushed a DoS-grade VOLUME. If the flood got through but the achieved rate stayed BELOW
# this many Mbit/s, we can't conclude the anti-DoS control is absent (the test simply
# never reached the rate it triggers at) -> INCONCLUSIVE, not a false SUCCESS/finding.
# Default 50 Mbit/s = a conservative "real DoS volume" floor; set it to the SD-WAN's
# documented threshold (e.g. 84) for a tight fit, or 0 to disable the gate.
MIN_MBPS = _int_env("HARNESS_ICMP_MIN_MBPS", 50, lo=0)
# A near-TOTAL loss can't be self-congestion: a saturated uplink still delivers SOME
# packets, so ~100% loss (with a working baseline) is an active in-path BLACKHOLE /
# anti-DoS ban that dropped the WHOLE flood (the "DOS detected" signature) — a control,
# regardless of the achieved-vs-target rate or the achieved volume. This OVERRIDES the
# SATURATION_FRAC / MIN_MBPS self-congestion demotions, which only apply to PARTIAL loss
# (when an anti-DoS bans the source mid-send the achieved rate ALSO collapses, which would
# otherwise masquerade as a thin-uplink ceiling and hide the control — the false PASS a
# real "DOS detected" produced). >= this % loss at a knee => the control dropped it all.
TOTAL_LOSS_PCT = _int_env("HARNESS_ICMP_TOTAL_LOSS_PCT", 99, lo=1)
# SOURCE UPLINK capacity (Mbit/s), operator-declared — the ONE thing that disambiguates a
# low-volume loss knee. SD-WANs are tuned DIFFERENTLY per site: one polices on bits/sec at
# ~84 Mbit/s, another drops at a LOW pps/bandwidth (a 2,100 pps flood can get DENIED at ~24
# Mbit/s). At that low volume a single source CANNOT tell a low-threshold policer from its
# OWN uplink/CPU choking — both drop packets the host "sent". The achieved-rate/MIN_MBPS
# demotion therefore can't PASS such a knee (that buries a real DENY as a false SUCCESS —
# the field bug) NOR BLOCK it (that credits an unproven control — the earlier thin-uplink
# flip). Default: such a knee is INCONCLUSIVE. If the operator DECLARES the uplink (measure
# once: iperf3 / a speedtest), a loss knee at a bandwidth with clear HEADROOM below it can't
# be the uplink -> it is a downstream drop -> the target policed it -> BLOCKED. Per-site:
# set HARNESS_ICMP_UPLINK_MBPS to the tester's real uplink at each vantage.
UPLINK_MBPS = _int_env("HARNESS_ICMP_UPLINK_MBPS", 0, lo=0)
# Noise handling: ICMP-reply loss over the internet jitters, so a single sample can flip
# the verdict. Take SAMPLES measurements and use the MEDIAN (one bad sample can't decide).
# And if the BASELINE itself is already lossy (>= NOISE_FLOOR %) the path/host is noisy, so
# any PASS/BLOCKED is tagged low-confidence. 0 disables the respective behaviour.
SAMPLES = _int_env("HARNESS_ICMP_SAMPLES", 3, lo=1)
NOISE_FLOOR = _int_env("HARNESS_ICMP_NOISE_FLOOR", 10, lo=0)
# RTT shaping is a SECONDARY signal and noisy: on a fast/local link, flooding a
# target bumps its avg RTT from queueing on ITS OWN NIC/CPU — not the boundary.
# A sub-ms baseline makes that look like a huge multiple, so require BOTH a large
# multiple AND a meaningful absolute latency floor before calling it shaping.
RTT_INFLATION = 6.0        # flood avg RTT >= Nx baseline, AND ...
RTT_ABS_FLOOR = 150.0      # ... flood avg RTT >= this many ms absolute => shaping

# Rate RAMP (pps). Instead of one arbitrary flood that either trips the appliance
# or doesn't, the module steps UP through these rates and finds the KNEE — the
# lowest rate where delivery drops / RTT inflates = the MEASURED anti-DoS policing
# threshold. Sangfor NGAF / Forcepoint NGFW anti-DoS thresholds are NOT published
# and are per-config (across vendors they span ~10–1000s pps, or are bits/sec-based
# — hence the near-MTU FLOOD_SIZE so a bandwidth policer is exercised too), so we
# MEASURE the knee rather than guess a number. Each step also reports achieved
# Mbit/s. Override the whole ramp with HARNESS_ICMP_RAMP="200,1000,5000,...".
RAMP_PPS = _list_env("HARNESS_ICMP_RAMP", [1000, 5000, 20000, 60000, 120000, 250000])
STEP_SECONDS = _int_env("HARNESS_ICMP_STEP_SECONDS", 4)   # seconds per ramp step

META = {
    "id": "icmp_flood",
    "name": "ICMP Flood (DoS)",
    "category": "Network Exploitation",
    # DEAD last (order 101), AFTER ssh_brute (order 100). A full ICMP flood trips
    # this SD-WAN's anti-DoS protection and — as seen live against the Sangfor
    # (the blacklist WARN fires the instant icmp finishes) — that source ban is
    # PERSISTENT, outlasting the smart-halt wait window. So anything that runs
    # AFTER icmp gets stranded as a false BLOCKED/SUSPECT (that's exactly how
    # ssh_brute was poisoned when icmp ran before it). Running icmp dead-last means
    # ssh_brute and every other module get a clean, un-banned test first; icmp's
    # OWN verdict is still measured DURING the flood (the rate-limit/shaping is
    # observed in-flight, before the ban fully latches), so icmp itself still earns
    # a real BLOCKED-RATELIMIT / PASS. (Operator request, ORG2026-70: icmp_flood is
    # the final attack executed.)
    "order": 101,
    "test_type": "dos",
    "control": "ICMP rate-limit / flood (DoS) protection",
    "fix": "SD-WAN",
    "mitre": ['T1498.001'],
    "cwe": ['CWE-400'],
    "tactic": 'Impact',
    # hping3 is PREFERRED but not hard-required: without it the Python fallback
    # runs, so it isn't in requires (which would PREREQ-MISSING the whole module).
    # ping is the one true dependency (the baseline leg).
    "requires": ["ping"],
    "needs_root": True,   # a real ICMP flood needs raw sockets (root / CAP_NET_RAW)
    "serial": True,       # DoS: must run alone (don't overlap other tests)
    "run_last": True,     # a flood can trip anti-DoS rate-limiting/blacklist of the
                          # source — run after everything else so it can't contaminate
                          # other modules' verdicts
    "os_supported": ["Linux"],   # uses `ping -c/-i` + hping3/raw ICMP (Linux-only)
    "ports": [("icmp", None)],   # ICMP, not a TCP/UDP port
    # SUCCESS = the high-rate flood was delivered (boundary didn't rate-limit it).
    # Anchored (^) so it can't match incidental words elsewhere in tool output.
    "success_regex": r"^PASS",
    # BLOCKED = the boundary policed the flood (differential rate-limit / RTT
    # shaping), or an outright network-layer block. A privilege/tooling failure
    # (FLOOD-PRIV-ERROR) must NOT match here — the flood never ran, so it is not
    # evidence the control worked; it falls to NO-RESULT instead.
    "blocked_regex": r"^BLOCKED-|No route to host|Network is unreachable|host unreachable",
}

# markers that mean the flood never actually sent (privilege/tooling failure) —
# NOT evidence the control worked.
_PRIV_ERR_MARKERS = ("operation not permitted", "raw socket", "permission denied",
                     "a password is required", "a terminal is required", "sudo:")


def _parse_loss(text):
    """Percent packet loss from a ping/hping3 statistics block, or None."""
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", text or "")
    return float(m.group(1)) if m else None


def _parse_rtt_avg(text):
    """Average RTT (ms) from a ping ('rtt .. = a/b/c/d') or hping3
    ('round-trip .. = a/b/c') statistics line, or None."""
    m = re.search(r"(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)/", text or "")
    return float(m.group(1)) if m else None


def _parse_sent(text):
    """Packets actually transmitted, from a ping/hping3 'N packets transmitted' line."""
    m = re.search(r"(\d+)\s+packets transmitted", text or "")
    return int(m.group(1)) if m else None


def _rate_report(sent, seconds, size, target_pps):
    """(rate_str, source_limited) describing the load ACTUALLY pushed. A single host
    over the internet usually can't reach the configured pps (NIC/CPU/link cap), so a
    PASS must report the REAL achieved rate — otherwise 'delivered @ ~20000 pps'
    overstates it and a below-threshold PASS reads as 'no policing' when the control
    simply was never reached. source_limited flags that the achieved rate fell well
    short of the target (the bottleneck is here, not the boundary)."""
    if not sent or not seconds or seconds <= 0:
        return ("~%s pps (configured target)" % f"{target_pps:,}", False)
    pps = sent / seconds
    mbps = sent * ((size or 0) + 28) * 8 / seconds / 1e6   # +28 = IPv4(20)+ICMP(8) headers
    return ("~%s pps / ~%d Mbit/s ACHIEVED over %ds (configured target ~%s pps)"
            % (f"{pps:,.0f}", mbps, seconds, f"{target_pps:,}"), pps < 0.5 * target_pps)


def _fmt(x, nd=0):
    """Format a number for the ramp table, or '?' for None."""
    return "?" if x is None else f"{x:,.{nd}f}"


def _knee_signals(loss, rtt, base_loss, base_rtt):
    """(loss_jump, rtt_jump) for a ramp step vs baseline: loss jumped
    >= RATE_LIMIT_DELTA points, and/or RTT inflated >= RTT_INFLATION x baseline
    AND >= RTT_ABS_FLOOR ms (the floor keeps LAN queueing from faking it)."""
    loss_jump = (loss is not None and base_loss is not None
                 and (loss - base_loss) >= RATE_LIMIT_DELTA)
    rtt_jump = (base_rtt and rtt and base_rtt > 0
                and rtt / base_rtt >= RTT_INFLATION and rtt >= RTT_ABS_FLOOR)
    return bool(loss_jump), bool(rtt_jump)


def _is_knee(loss, rtt, base_loss, base_rtt):
    """True if a ramp step shows a knee at all (loss OR RTT). See _knee_signals."""
    loss_jump, rtt_jump = _knee_signals(loss, rtt, base_loss, base_rtt)
    return loss_jump or rtt_jump


def _knee_verdict(loss, rtt, base_loss, base_rtt, apps, pps, ambps):
    """Classify a ramp step's knee and ATTRIBUTE it — pure, so it's unit-testable.

    The ONE physical question: were the lost packets DROPPED DOWNSTREAM (a target control)
    or did they never make it off this host / die at this host's OWN uplink (self-congestion)?
    The discriminator is whether the host actually PUT THE OFFERED RATE ON THE WIRE:
      * if hping3 transmitted ~the target rate (achieved >= SATURATION_FRAC x target) and the
        replies were lost, the packets LEFT this NIC and were dropped downstream -> the TARGET
        policed them (a single host over the internet does not saturate a remote target at
        these volumes, so a drop is the boundary). This is scored "control" by DEFAULT —
        trusting that the tester's uplink is not the choke, which is true for a normal
        server/VPS tester and is what makes a LOW-threshold policer (the 2,100-pps DENY the
        field hit at ~24 Mbit/s) read BLOCKED without any tuning.
      * if the host could NOT even transmit the offered rate (achieved << target), the loss is
        a LOCAL CPU/NIC/raw-socket send bottleneck -> self-congestion -> "inconclusive".

    A thin-uplink tester (whose ISP uplink, not the NIC, is the bottleneck — invisible to
    local counters, so it can still read "reached") OVERRIDES the default by DECLARING the
    uplink (UPLINK_MBPS): a knee whose bandwidth is at/above the uplink's usable headroom is
    then attributed to that uplink -> "inconclusive", not a false BLOCKED.

    Returns: None (no knee) | "control" (BLOCKED) | "inconclusive" (INCONCLUSIVE).
    """
    loss_jump, rtt_jump = _knee_signals(loss, rtt, base_loss, base_rtt)
    if not (loss_jump or rtt_jump):
        return None
    # DECISIVE by default: a delivery collapse on a high-rate flood (while ordinary pings
    # work) is the boundary policing it -> "control" (BLOCKED). The ONLY opt-out is a
    # thin-link tester who DECLARES its uplink and whose loss appeared at/above that uplink's
    # usable headroom — then it's the tester's OWN uplink, not the target -> "inconclusive".
    # By default UPLINK_MBPS=0, so there is NO inconclusive: every knee is control. (A
    # near-TOTAL loss is additionally the blackhole/"DOS detected" case, flagged in run().)
    if UPLINK_MBPS and ambps is not None and ambps >= SATURATION_FRAC * UPLINK_MBPS \
            and (loss is None or loss < TOTAL_LOSS_PCT):
        return "inconclusive"
    return "control"


# TCP ports probed to decide "is the host actually UP?" when ICMP is 100% lost,
# ordered by how commonly they answer on a Windows DC / Linux server / appliance.
_LIVENESS_PORTS = (445, 80, 443, 22, 389, 3389, 8080, 139, 135, 21, 23, 53, 1135, 4445)


def _host_up_via_tcp(target, ctx=None, timeout=1.0, budget=6.0):
    """Is the host's TCP stack reachable? Returns (up, how). ANY probed port that
    is open OR explicitly refuses with a RST proves the host is UP and reachable;
    only an all-timeouts result (silent drop) leaves it unconfirmed. Used when
    ICMP is 100% lost: a confirmed-up host with 0 ICMP = ICMP filtered (a real
    BLOCK), whereas an unconfirmable host is genuinely indeterminate. Honours
    ctx egress bind; bounded by `budget` so it can never hang the run. The verdict
    it feeds comes purely from what the probes observed — no posture/policy
    reliance (ORG2026-70)."""
    deadline = time.time() + budget
    for port in _LIVENESS_PORTS:
        if time.time() > deadline:
            break
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if ctx is not None:
                try:
                    ctx.bind_source(sk)
                except Exception:
                    pass
            sk.settimeout(timeout)
            rc = sk.connect_ex((target, port))
        except OSError:
            continue
        finally:
            try:
                sk.close()
            except OSError:
                pass
        if rc == 0:
            return True, f"tcp/{port} (open)"
        if rc == errno.ECONNREFUSED:
            return True, f"tcp/{port} (RST — stack reachable)"
    return False, None


# --------------------------------------------------------------------------
# Pure-Python ICMP flood fallback (used only when hping3 is absent)
# --------------------------------------------------------------------------
def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF




def _open_icmp_socket():
    """(sock, mode) — try unprivileged SOCK_DGRAM ICMP first (works where
    net.ipv4.ping_group_range allows it), then a raw socket (needs root)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        return s, "dgram(unprivileged)"
    except (PermissionError, OSError):
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)  # may raise
    return s, "raw(root)"


def _flood_packet():
    """One ICMP echo padded to FLOOD_SIZE payload bytes — so the Python fallback sends
    the SAME bandwidth-grade packet hping3 would (the old 17-byte payload meant the real
    wire rate was ~30x below what the Mbit/s report assumed). FLOOD_SIZE=0 => header-only
    (pure pps test). For SOCK_DGRAM the kernel rewrites id/checksum; the fixed packet is
    fine either way, so we build it ONCE and blast it (no per-packet Python cost)."""
    pid = os.getpid() & 0xFFFF
    base = b"mygovnet-bas-icmp"
    if FLOOD_SIZE and FLOOD_SIZE > 0:
        payload = (base * (FLOOD_SIZE // len(base) + 1))[:FLOOD_SIZE]
    else:
        payload = b""
    header = struct.pack("!BBHHH", 8, 0, 0, pid, 1)
    chk = _checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, chk, pid, 1) + payload


def _py_icmp_flood(target, seconds, result):
    """Flood ICMP echo to target for `seconds` using FLOOD_WORKERS parallel senders,
    each blasting one precomputed FLOOD_SIZE packet. Records total sent / mode / error
    in `result`. Runs in a background thread; fully crash-safe."""
    try:
        probe, mode = _open_icmp_socket()
        probe.close()
    except (PermissionError, OSError) as e:
        result["error"] = f"{e.__class__.__name__}: {e}"
        return
    result["mode"] = mode
    pkt = _flood_packet()
    dest = (target, 0)
    deadline = time.time() + seconds
    counts, errs = [], []
    lock = threading.Lock()

    def _worker():
        try:
            s, _ = _open_icmp_socket()
        except OSError as e:
            with lock:
                errs.append(f"{e.__class__.__name__}: {e}")
            return
        c = 0
        try:
            while time.time() < deadline:
                try:
                    s.sendto(pkt, dest)
                    c += 1
                except OSError as e:
                    with lock:
                        errs.append(f"{e.__class__.__name__}: {e}")
                    break
        finally:
            try:
                s.close()
            except OSError:
                pass
            with lock:
                counts.append(c)

    ths = [threading.Thread(target=_worker, daemon=True) for _ in range(FLOOD_WORKERS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(seconds + 5)
    sent = sum(counts)
    result["sent"] = sent
    if sent == 0 and errs:
        result["error"] = errs[0]


def _median(xs):
    """Median of the non-None values, or None if all are None."""
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    return xs[len(xs) // 2]


def _lowconf(base_loss):
    """Caveat appended to a PASS/BLOCKED verdict when the BASELINE itself is already lossy
    (>= NOISE_FLOOR): the measurement is noisy, so the verdict can flip between runs and
    shouldn't be read as definitive."""
    if NOISE_FLOOR and base_loss is not None and base_loss >= NOISE_FLOOR:
        return (f"  [LOW-CONFIDENCE: baseline ICMP already lost {base_loss:.0f}% at NORMAL rate — "
                "the path/host is noisy (host ICMP-reply rate-limit / internet jitter), so this "
                "verdict can flip run-to-run. Use -i N and read the distribution, or --appliance "
                "dual-path, for a trustworthy result.]")
    return ""


def _ratelimit_caveat():
    """Confidence tag appended to EVERY BLOCKED-RATELIMIT verdict. A single source rarely
    reaches a carrier/SD-WAN anti-DoS ceiling, so a 'knee' found from one host is more
    often the TARGET's own kernel ICMP-reply rate-limit (sysctl net.ipv4.icmp_ratelimit/
    icmp_ratemask) or the cloud provider's edge than a dedicated anti-DoS control. The
    verdict is also vantage-dependent: a raw-socket host (hping3) can find a knee where a
    WSL1 datagram flood self-congests and reads PASS. So BLOCKED-RATELIMIT here means
    'the high-rate ICMP was policed somewhere in path', NOT proof of an SD-WAN control."""
    return ("  [CONFIDENCE: single-source — a knee at this rate is likely the TARGET kernel's "
            "ICMP-reply rate-limit or the cloud/ISP edge, NOT necessarily a dedicated SD-WAN "
            "anti-DoS; and the verdict varies by vantage (raw-socket host finds a knee where a "
            "WSL1 datagram flood self-congests -> PASS). Confirm WHICH device policed it via the "
            "appliance/host logs, or test through the real boundary (--appliance dual-path).]")


def _ping_once(target, count=BASELINE_COUNT, interval=BASELINE_INTERVAL):
    """One ping sample: (loss%, avg_rtt_ms, raw_text)."""
    try:
        p = subprocess.run(
            ["ping", "-c", str(count), "-i", str(interval), target],
            capture_output=True, text=True,
            timeout=int(count * float(interval)) + 15, stdin=subprocess.DEVNULL)
        return _parse_loss(p.stdout), _parse_rtt_avg(p.stdout), p.stdout
    except Exception as e:
        return None, None, f"[ping error] {e}"


def _sampled_loss_rtt(target, samples=None):
    """Run several ping samples and return (median_loss, median_rtt, combined_text) —
    smooths internet jitter so one bad sample can't flip the verdict."""
    n = samples or SAMPLES
    losses, rtts, texts = [], [], []
    for i in range(n):
        lo, rt, tx = _ping_once(target)
        losses.append(lo)
        rtts.append(rt)
        texts.append((f"[sample {i+1}/{n}] " if n > 1 else "") + tx.strip())
    return _median(losses), _median(rtts), "\n".join(texts)


def _baseline(target):
    """Normal-rate ICMP reference (median of SAMPLES): (loss%, avg_rtt_ms, raw_text)."""
    return _sampled_loss_rtt(target)


def _hping_flood_at(target, pps, size, seconds):
    """One RAMP STEP: counted hping3 ICMP at ~`pps` for `seconds`. Counted (-c) +
    fast (-i uX) so hping3 prints a real delivery-ratio block (unlike --flood,
    which discards replies). Returns (loss%, avg_rtt_ms, sent, raw_text)."""
    import core
    interval_us = max(1, 1_000_000 // max(1, pps))
    count = max(1, pps * seconds)
    prefix = (["timeout", str(seconds)] if shutil.which("timeout") else [])
    cmd = prefix + core.sudo_prefix() + ["hping3", "-1", "-c", str(count), "-i", "u%d" % interval_us]
    if size > 0:
        cmd += ["-d", str(size)]              # payload bytes -> bandwidth flood
    cmd += [target]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=seconds + 10, stdin=subprocess.DEVNULL)
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = (((e.output or "") if isinstance(e.output, str) else "")) + "\n[step hit wall-clock cap]"
    return _parse_loss(out), _parse_rtt_avg(out), _parse_sent(out), out


def run(target, ctx):
    out = [f"# ICMP flood vs {target} — boundary anti-DoS test: RAMP the rate to find the "
           f"policing knee (baseline {BASELINE_COUNT}-ping; ramp {RAMP_PPS} pps"
           + (f" x {FLOOD_SIZE}B" if FLOOD_SIZE else "") + f" x {STEP_SECONDS}s/step)"]

    # ---- leg 1: normal-rate baseline (does ordinary ICMP work at all?) --------
    base_loss, base_rtt, base_txt = _baseline(target)
    out.append("## baseline (normal-rate ICMP)")
    out.append(base_txt.strip())
    out.append(f"baseline: loss={base_loss}%  avg_rtt={base_rtt}ms")
    base_ok = base_loss is not None and base_loss <= LOW_LOSS

    # Baseline (near-)100% lost => no rate differential to measure. Decide via TCP
    # liveness: host up on TCP + ICMP gone = ICMP filtered (BLOCKED); can't confirm
    # up = INCONCLUSIVE (down / source quarantined). Verdict from the test only.
    if not base_ok:
        up, how = _host_up_via_tcp(target, ctx) if base_loss is not None else (False, None)
        if up:
            out.append(
                f"BLOCKED-ICMP-FILTERED: normal-rate ICMP lost {base_loss}% but the host is "
                f"confirmed UP via {how} — ICMP is dropped/filtered end-to-end while TCP passes, "
                "so the boundary/host BLOCKS ICMP (control held). A real block, not an "
                "unreachable host.")
        else:
            out.append(
                f"[INCONCLUSIVE] even normal-rate ICMP lost {base_loss}% and TCP liveness couldn't "
                "confirm the host is up (no port answered) — can't separate a down/unreachable "
                "host (or a source just quarantined) from ICMP filtered entirely. Review raw log.")
        return "\n".join(out)

    # ---- leg 2: RAMP the rate and find the KNEE (measured policing threshold) --
    hping_privfail = False
    if shutil.which("hping3"):
        out.append(f"## ramp (hping3): step the ICMP rate up — the knee = first rate the boundary "
                   f"polices (baseline loss {_fmt(base_loss, 1)}%, rtt {_fmt(base_rtt, 1)}ms)")
        knee = None
        ambiguous = None       # a loss knee a single source can't attribute (policer vs uplink)
        max_pps = max_mbps = 0.0        # highest rate the source PUSHED (any step)
        clean_pps = clean_mbps = 0.0    # highest rate actually DELIVERED clean (no knee)
        parsed_any = False     # did ANY ramp step yield a parseable delivery stat?
        egress_denied = None    # a higher step was EPERM-blocked at the SENDER after a clean step
        for pps in RAMP_PPS:
            loss, rtt, snt, raw = _hping_flood_at(target, pps, FLOOD_SIZE, STEP_SECONDS)
            # "operation not permitted" / "raw socket" in hping3's output is AMBIGUOUS:
            #   * at the FIRST step (no clean step yet) it is a genuine raw-socket PRIVILEGE
            #     failure (no cap_net_raw / WSL1) -> fall back to the Python datagram flood.
            #   * AFTER a clean step already used the raw socket fine, a later EPERM is NOT a
            #     privilege problem — the kernel/egress refused to SEND the flood at this rate
            #     (a LOCAL egress firewall, a host-based SD-WAN agent, or in-path enforcement
            #     that NACKs with EPERM, e.g. iptables OUTPUT -j DROP). That is the control
            #     DENYING the flood -> BLOCKED, not a tooling failure / false PASS.
            if any(mk in raw.lower() for mk in _PRIV_ERR_MARKERS):
                if parsed_any:
                    egress_denied = {"pps": clean_pps or None, "mbps": clean_mbps or None,
                                     "target": pps}
                    break
                out.append("note: hping3 can't open a raw socket here (no cap_net_raw / WSL1) — "
                           "falling back to the Python datagram-ICMP flood (the path `ping` uses).")
                hping_privfail = True
                break
            apps = (snt / STEP_SECONDS) if snt else None
            ambps = (snt * ((FLOOD_SIZE or 0) + 28) * 8 / STEP_SECONDS / 1e6) if snt else None
            max_pps = max(max_pps, apps or 0.0)
            max_mbps = max(max_mbps, ambps or 0.0)
            out.append("  step target ~%s pps -> achieved ~%s pps / ~%s Mbit/s . loss=%s%% rtt=%sms"
                       % (f"{pps:,}", _fmt(apps), _fmt(ambps), _fmt(loss, 1), _fmt(rtt, 1)))
            verdict = _knee_verdict(loss, rtt, base_loss, base_rtt, apps, pps, ambps)
            if verdict == "control":
                knee = {"pps": apps, "mbps": ambps, "target": pps, "loss": loss, "rtt": rtt}
                break
            elif verdict == "inconclusive":
                ambiguous = {"pps": apps, "mbps": ambps, "target": pps, "loss": loss, "rtt": rtt}
                break
            elif loss is None and rtt is None:
                # UNPARSEABLE step: hping3 emitted no delivery stats (timed out / its output was
                # lost when the flood tripped a mid-send ban). This is NOT clean delivery — do
                # NOT let it masquerade as "no policing" (a false PASS). Record nothing.
                pass
            else:
                # step delivered clean (no knee) -> this is a rate the flood was actually
                # DELIVERED at. Track it SEPARATELY from max_pps (which includes a lossy
                # knee step): reporting max as "delivered up to ..." when the knee step is
                # the max contradicts the very loss we attribute to that step.
                parsed_any = True
                clean_pps = max(clean_pps, apps or 0.0)
                clean_mbps = max(clean_mbps, ambps or 0.0)

        if not hping_privfail:
            if egress_denied:
                # A clean lower step used the raw socket fine, then a higher step was refused
                # with EPERM at the SENDER = the egress/host-based control DENIED the flood
                # above the clean rate. Not a privilege failure (the socket worked) and not a
                # false PASS — a control held.
                out.append(
                    "BLOCKED-EGRESS-DENIED: the ICMP flood was delivered up to ~%s pps / ~%s Mbit/s, "
                    "then the egress REFUSED to send it at ~%s pps (EPERM at the sender — a local "
                    "egress firewall, a host-based SD-WAN agent, or in-path enforcement dropping the "
                    "flood, e.g. an OUTPUT -j DROP policer). The raw socket worked at the lower rate, "
                    "so this is the control denying the high-rate flood, NOT a privilege/tooling "
                    "failure. The threshold is at/below ~%s pps."
                    % (_fmt(egress_denied["pps"]), _fmt(egress_denied["mbps"]),
                       f"{egress_denied['target']:,}", f"{egress_denied['target']:,}")
                    + _lowconf(base_loss) + _ratelimit_caveat())
            elif knee and knee["loss"] is not None and knee["loss"] >= TOTAL_LOSS_PCT:
                # TOTAL loss: the whole flood was dropped in transit while ordinary pings
                # worked — an anti-DoS / blackhole DETECTED the flood and dropped (or banned)
                # it. Not self-congestion (a saturated uplink still delivers some packets).
                out.append(
                    "BLOCKED-DOS-DETECTED: the high-rate ICMP flood was ENTIRELY dropped (%s%% loss "
                    "vs %s%% baseline) at ~%s pps / ~%s Mbit/s (target %s pps) while normal-rate pings "
                    "worked — an anti-DoS control DETECTED the flood and blackholed/banned it in transit "
                    "(the 'DOS detected' signature; control held). The threshold is at/below this rate."
                    % (_fmt(knee["loss"], 1), _fmt(base_loss, 1), _fmt(knee["pps"]), _fmt(knee["mbps"]),
                       f"{knee['target']:,}")
                    + _lowconf(base_loss) + _ratelimit_caveat())
            elif knee:
                # A high-rate flood collapsed in delivery while ordinary pings worked = the
                # boundary policed it -> BLOCKED. Report the measured rate. Two nuances:
                #  * if the source did NOT reach the target rate, the policing threshold is
                #    at/below the rate it DID push (note it, don't claim the full rate);
                #  * a LOW-volume knee (< MIN_MBPS, no declared uplink) carries a caveat: a
                #    thin-uplink tester could instead be hitting its OWN uplink -> declare
                #    HARNESS_ICMP_UPLINK_MBPS to flip such a knee to INCONCLUSIVE.
                reached = bool(knee["pps"] is not None and knee["target"]
                               and knee["pps"] >= SATURATION_FRAC * knee["target"])
                transmit = ("The source transmitted this rate but the replies were dropped downstream"
                            if reached else
                            "The source pushed ~%s pps (short of the ~%s pps target) and even that was "
                            "dropped — the threshold is at/below this rate"
                            % (_fmt(knee["pps"]), f"{knee['target']:,}"))
                low_vol = bool(MIN_MBPS and knee["mbps"] is not None and knee["mbps"] < MIN_MBPS
                               and not UPLINK_MBPS)
                assume_note = (("  [ASSUMES the tester uplink exceeds this ~%s Mbit/s — the host put this "
                                "rate on the wire and the replies were dropped downstream. If THIS host's "
                                "uplink is itself near this bandwidth the loss could be your OWN uplink; "
                                "set HARNESS_ICMP_UPLINK_MBPS=<your uplink Mbit/s> to flip it to "
                                "INCONCLUSIVE.]") % _fmt(knee["mbps"])) if low_vol else ""
                out.append(
                    "BLOCKED-RATELIMIT: ICMP policing kicked in at ~%s pps / ~%s Mbit/s (target %s pps) "
                    "— loss %s%% vs %s%% baseline, rtt %sms vs %sms. %s = the MEASURED anti-DoS threshold "
                    "(Sangfor/Forcepoint defaults aren't published — the ramp measured it); the control "
                    "holds at/above this rate."
                    % (_fmt(knee["pps"]), _fmt(knee["mbps"]), f"{knee['target']:,}", _fmt(knee["loss"], 1),
                       _fmt(base_loss, 1), _fmt(knee["rtt"], 1), _fmt(base_rtt, 1), transmit)
                    + assume_note + _lowconf(base_loss) + _ratelimit_caveat())
            elif ambiguous:
                # Only reachable when a thin-link tester DECLARED its uplink and the loss
                # appeared at/above that uplink's usable headroom -> the tester's OWN uplink
                # saturated, not the target -> INCONCLUSIVE (the opt-in escape hatch). Without a
                # declared uplink there is NO inconclusive — every knee above is BLOCKED.
                out.append(
                    "[INCONCLUSIVE] a loss knee appeared at ~%s pps / ~%s Mbit/s (loss %s%% vs %s%% "
                    "baseline), AT/ABOVE the declared tester uplink's usable headroom (%d Mbit/s) — that "
                    "is the tester's OWN uplink saturating, not the target. To get a target verdict: "
                    "flood from a host with a fatter uplink / more sources (fleet.py), lower "
                    "HARNESS_ICMP_UPLINK_MBPS if it is set too low, or test through --appliance dual-path."
                    % (_fmt(ambiguous["pps"]), _fmt(ambiguous["mbps"]), _fmt(ambiguous["loss"], 1),
                       _fmt(base_loss, 1), UPLINK_MBPS)
                    + _lowconf(base_loss))
            elif not parsed_any:
                # No step produced a parseable delivery stat (every hping3 step timed out or lost
                # its output) AND no knee fired — we measured NOTHING, so this is NOT a PASS. A
                # flood that tripped a mid-send ban can wipe hping3's stats; fall to the datagram
                # fallback below, which measures delivery with independent ping samples.
                out.append("note: the hping3 ramp produced NO parseable delivery stats on any step "
                           "(timed out / output lost) — falling back to the Python datagram flood "
                           "to measure delivery independently.")
                hping_privfail = True   # reuse the fallback path (it re-measures via ping samples)
            elif MIN_MBPS and max_mbps < MIN_MBPS:
                # Delivered with no policing knee, but below DoS-grade volume. DECISIVE: the
                # boundary did NOT police it -> PASS (a flood that reached the target is a finding),
                # with an honest UNDER-POWERED caveat (a higher-rate anti-DoS could exist above this).
                out.append(
                    "PASS: the ICMP flood was DELIVERED (<=%d%% loss) and NOT policed up to the most "
                    "this source could push (~%s Mbit/s / ~%s pps) — the boundary did not rate-limit "
                    "it at this volume (finding).  [LOW-CONFIDENCE / under-powered: that is BELOW the "
                    "%d Mbit/s DoS-volume floor (HARNESS_ICMP_MIN_MBPS), so a higher-rate anti-DoS "
                    "could still trigger above it — flood from a host with real raw sockets (hping3, "
                    "not WSL1), raise HARNESS_ICMP_PPS / HARNESS_ICMP_SIZE / extend HARNESS_ICMP_RAMP, "
                    "or drive MULTIPLE sources (fleet.py) to push past the threshold.]"
                    % (LOW_LOSS, _fmt(max_mbps), _fmt(max_pps), MIN_MBPS))
            else:
                out.append(
                    "PASS: NO ICMP policing observed across the ramp — the flood was delivered up to the "
                    "most this source could push (~%s pps / ~%s Mbit/s) at <=%d%% loss. The anti-DoS "
                    "threshold, if any, is ABOVE that, and a single host usually can't reach a carrier/"
                    "SD-WAN ceiling: raise HARNESS_ICMP_SIZE (bigger packets for a bits/sec policer), "
                    "extend HARNESS_ICMP_RAMP higher, use a fatter/closer link, or drive MULTIPLE "
                    "sources (fleet.py) to push past the threshold."
                    % (_fmt(max_pps), _fmt(max_mbps), LOW_LOSS) + _lowconf(base_loss))
            # a verdict was emitted above UNLESS the not-parsed_any branch flipped us to the
            # fallback (hping_privfail) — in that case fall through to the datagram flood.
            if not hping_privfail:
                return "\n".join(out)

    # ---- leg 2 (fallback): no hping3 (or its raw socket failed) -> Python flood --
    out.append("## high-rate flood (engine: python datagram-ICMP fallback — %s; no rate ramp, "
               "best-effort)" % ("hping3 raw socket unavailable" if hping_privfail
                                 else "hping3 not installed"))
    py_result = {}
    th = threading.Thread(target=_py_icmp_flood, args=(target, FLOOD_SECONDS, py_result), daemon=True)
    th.start()
    try:
        # measure delivery with SAMPLES fast pings DURING the flood and take the median,
        # so one jittery sample can't flip the verdict (fast -i so they fit the window).
        flood_loss, flood_rtt, ftext = _sampled_loss_rtt(target)
        out.append(ftext)
    finally:
        th.join(FLOOD_SECONDS + 5)
    if py_result.get("error"):
        out.append(f"python flood error: {py_result['error']}")
        out.append(
            "FLOOD-PRIV-ERROR: the Python ICMP fallback could not send — unprivileged ICMP is "
            "disabled and we're not root. Fix ONE of: (a) install hping3 (sudo apt install hping3); "
            "(b) run as root; or (c) sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'.")
        return "\n".join(out)
    sent = py_result.get("sent")
    rate_str, source_limited = _rate_report(sent, FLOOD_SECONDS, FLOOD_SIZE, FLOOD_PPS)
    ach_mbps = (sent * ((FLOOD_SIZE or 0) + 28) * 8 / FLOOD_SECONDS / 1e6) if sent else 0.0
    out.append(f"python flood: sent {sent} ICMP echoes via {py_result.get('mode', '?')}; "
               f"during-flood loss={flood_loss}%")
    if flood_loss is None:
        out.append("[ERROR] could not parse the flood's delivery ratio from ping (no stats line) "
                   "— tool fault, review raw log.")
        return "\n".join(out)
    # A near-TOTAL during-flood loss with a WORKING baseline is unambiguous even for the
    # datagram fallback: the Linux kernel ICMP-reply rate-limit (the usual cause of partial
    # reply-loss here) still answers SOME under load — it throttles to a RATE, it does not
    # blackhole. ~100% loss while normal pings worked = an in-path blackhole/ban dropped the
    # WHOLE flood (the "DOS detected" / SD-WAN DENY signature) -> BLOCKED, not a false PASS.
    if base_loss is not None and base_loss <= LOW_LOSS and flood_loss >= TOTAL_LOSS_PCT:
        out.append(
            "BLOCKED-DOS-DETECTED: the ICMP flood was ENTIRELY dropped (%.0f%% loss vs %.0f%% "
            "baseline) while normal-rate pings worked — an anti-DoS control DETECTED the flood and "
            "blackholed/banned it in transit (the 'DOS detected' / SD-WAN DENY signature; control "
            "held). A kernel ICMP-reply rate-limit throttles to a rate, it does not drop ALL replies, "
            "so this is an in-path block, not a host artifact.%s" % (flood_loss, base_loss,
                                                                     _ratelimit_caveat()))
        return "\n".join(out)
    # The DATAGRAM FALLBACK measures DELIVERY, not boundary policing. Echo-reply loss from a
    # single unprivileged source conflates three different things and cannot attribute between
    # them: (a) a boundary dropping the flood in transit, (b) the TARGET's OWN kernel ICMP-reply
    # rate-limit (net.ipv4.icmp_ratelimit — ON BY DEFAULT on every Linux host; it throttles the
    # host's REPLIES under any flood), and (c) attacker self-congestion. On a host with no SD-WAN
    # the reply-loss is (b): a host artifact, NOT a control. So the fallback no longer scores
    # BLOCKED (that produced false BLOCKEDs + run-to-run flip-flop); it reports the flood as
    # DELIVERED and defers any boundary-policing verdict to the hping3 raw-socket ramp (real
    # send-rate knee) or --appliance dual-path.
    msg = (f"PASS: the ICMP flood was DELIVERED to the target ({sent} echoes sent, {rate_str}) — "
           "the attack reached the host and no boundary was proven to stop it (finding: no "
           "confirmed ICMP DoS protection in path).")
    caveats = []
    if base_loss is not None and flood_loss - base_loss >= RATE_LIMIT_DELTA:
        caveats.append(
            "echo-reply loss rose to %.0f%% (vs %.0f%% baseline) with the round-trip staying flat "
            "(~%sms) — from a single datagram source that is most likely the TARGET's own kernel "
            "ICMP-reply rate-limit throttling its REPLIES, NOT a boundary anti-DoS; confirm a real "
            "boundary rate-limit with hping3's raw-socket ramp or --appliance dual-path"
            % (flood_loss, base_loss, _fmt(flood_rtt, 0)))
    elif flood_loss > LOW_LOSS:
        caveats.append(
            "echo-reply loss was %.0f%% — partial loss from a single source over the internet is "
            "noisy (host reply-throttle / jitter), not a boundary verdict" % flood_loss)
    if source_limited or (MIN_MBPS and ach_mbps < MIN_MBPS):
        caveats.append(
            "under-powered: only ~%s Mbit/s, below the %d Mbit/s DoS-volume floor (the datagram "
            "fallback is rate-capped on WSL1) — a higher-rate anti-DoS could still exist above "
            "this; use hping3 (raw sockets) or multiple sources (fleet.py)" % (_fmt(ach_mbps), MIN_MBPS))
    if caveats:
        msg += "  [LOW-CONFIDENCE: " + "; ".join(caveats) + ".]"
    out.append(msg + _lowconf(base_loss))
    return "\n".join(out)
