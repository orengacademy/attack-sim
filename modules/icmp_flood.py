"""ICMP Flood (DoS) — tests ICMP rate-limit / flood protection at the boundary.

The old model asked "did I DoS the target into packet loss?" — which needs a
volume a single host can't push over the internet, so it dead-ended at
"0% loss → inconclusive". Wrong question for a *boundary* control.

The right question an SD-WAN/segmentation control answers is "does the boundary
rate-limit or drop a high-rate ICMP flood?" — and THAT is measurable from one
host as a **differential**:

  1. baseline  — normal-rate ICMP (`ping -i 0.2`): does ordinary ICMP work at all?
  2. flood     — high-rate ICMP (`hping3 -1 -c N -i uX`, ~thousands of pps):
                 how much of MY OWN high-rate stream gets through, and how much
                 does its RTT inflate?

Verdict:
  * normal-rate ICMP works but the high-rate flood is largely dropped (or its RTT
    balloons) -> the boundary **rate-limited / dropped the flood** = BLOCKED
    (the control held — this is the classic signature of ICMP rate-limiting:
    low-rate passes, high-rate is policed).
  * the high-rate flood is delivered end-to-end -> the boundary does **NOT**
    rate-limit/block ICMP flooding = SUCCESS (a finding: deploy ICMP
    rate-limiting / DoS protection).
  * can't tell (both rates fail, or the flood never ran) -> NO-RESULT.

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
LOW_LOSS = 20              # <= this %: that rate is "getting through"
RATE_LIMIT_DELTA = 30      # flood loss this many points ABOVE baseline => policed
# RTT shaping is a SECONDARY signal and noisy: on a fast/local link, flooding a
# target bumps its avg RTT from queueing on ITS OWN NIC/CPU — not the boundary.
# A sub-ms baseline makes that look like a huge multiple, so require BOTH a large
# multiple AND a meaningful absolute latency floor before calling it shaping.
RTT_INFLATION = 6.0        # flood avg RTT >= Nx baseline, AND ...
RTT_ABS_FLOOR = 150.0      # ... flood avg RTT >= this many ms absolute => shaping

META = {
    "id": "icmp_flood",
    "name": "ICMP Flood (DoS)",
    "category": "Network Exploitation",
    # Near the end (order 99), just BEFORE ssh_brute (order 100). Both DoS/brute
    # floods run at the very end so the anti-DoS rate-limit / blacklist they trip
    # can't contaminate other modules; ssh_brute is DEAD last because its brute
    # blacklist outlives icmp's DoS lockout (which clears inside the wait window,
    # so icmp running just before ssh_brute doesn't strand it).
    "order": 99,
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


def _echo_packet(seq):
    pid = os.getpid() & 0xFFFF
    payload = b"mygovnet-bas-icmp"
    header = struct.pack("!BBHHH", 8, 0, 0, pid, seq & 0xFFFF)  # type 8 = echo
    chk = _checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, chk, pid, seq & 0xFFFF)
    return header + payload


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


def _py_icmp_flood(target, seconds, result):
    """Flood ICMP echo to target for `seconds`; records sent count / error in
    the `result` dict. Runs in a background thread."""
    try:
        sock, mode = _open_icmp_socket()
    except (PermissionError, OSError) as e:
        result["error"] = f"{e.__class__.__name__}: {e}"
        return
    result["mode"] = mode
    sock.setblocking(False)
    deadline = time.time() + seconds
    seq = sent = 0
    try:
        dest = (target, 0)
        while time.time() < deadline:
            try:
                sock.sendto(_echo_packet(seq), dest)
                sent += 1
                seq += 1
            except BlockingIOError:
                continue
            except OSError as e:
                result["error"] = f"{e.__class__.__name__}: {e}"
                break
    finally:
        sock.close()
    result["sent"] = sent


def _baseline(target):
    """Normal-rate ICMP reference: (loss%, avg_rtt_ms, raw_text)."""
    try:
        p = subprocess.run(
            ["ping", "-c", str(BASELINE_COUNT), "-i", BASELINE_INTERVAL, target],
            capture_output=True, text=True, timeout=BASELINE_COUNT * 1 + 15,
            stdin=subprocess.DEVNULL)
        return _parse_loss(p.stdout), _parse_rtt_avg(p.stdout), p.stdout
    except Exception as e:
        return None, None, f"[baseline ping error] {e}"


def _hping_flood(target):
    """High-rate counted ICMP via hping3; returns (loss%, avg_rtt_ms, raw_text).
    Counted (-c) + fast (-i uX) so hping3 prints a real delivery-ratio statistics
    block (unlike --flood, which discards replies)."""
    import core
    prefix = (["timeout", str(FLOOD_SECONDS)] if shutil.which("timeout") else [])
    cmd = prefix + core.sudo_prefix() + [
        "hping3", "-1", "-c", str(FLOOD_COUNT), "-i", "u%d" % FLOOD_INTERVAL_US]
    if FLOOD_SIZE > 0:
        cmd += ["-d", str(FLOOD_SIZE)]        # payload bytes -> bandwidth flood
    cmd += [target]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=FLOOD_SECONDS + 10, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        txt = (e.output or "") if isinstance(e.output, str) else ""
        return _parse_loss(txt), _parse_rtt_avg(txt), txt + "\n[flood hit wall-clock cap]"
    out = (p.stdout or "") + (p.stderr or "")
    return _parse_loss(out), _parse_rtt_avg(out), out


def run(target, ctx):
    out = [f"# ICMP flood vs {target} — boundary rate-limit test (baseline "
           f"{BASELINE_COUNT}-ping vs {FLOOD_COUNT}-pkt flood @ ~{FLOOD_PPS} pps"
           + (f", {FLOOD_SIZE}B payload" if FLOOD_SIZE else "") + ")"]

    # ---- leg 1: normal-rate baseline (does ordinary ICMP work at all?) --------
    base_loss, base_rtt, base_txt = _baseline(target)
    out.append("## baseline (normal-rate ICMP)")
    out.append(base_txt.strip())
    out.append(f"baseline: loss={base_loss}%  avg_rtt={base_rtt}ms")

    # ---- leg 2: high-rate flood (how much of my stream gets through?) ---------
    use_hping = shutil.which("hping3") is not None
    flood_loss = flood_rtt = None
    flood_txt = ""
    if use_hping:
        out.append("## high-rate flood (engine: hping3 -1, counted fast mode)")
        flood_loss, flood_rtt, flood_txt = _hping_flood(target)
        out.append(flood_txt.strip())
        # privilege/tooling failure => the flood never ran (NOT a control result)
        if any(mk in flood_txt.lower() for mk in _PRIV_ERR_MARKERS) and flood_loss is None:
            out.append(
                "FLOOD-PRIV-ERROR: hping3 could not run with the privileges it "
                "needs — the flood never ran. NOT evidence the control works. Fix "
                "ONE of: (a) sudo setcap cap_net_raw,cap_net_admin+eip $(which "
                "hping3); (b) a NOPASSWD sudoers rule for hping3; or (c) run as root.")
            return "\n".join(out)
        out.append(f"flood: loss={flood_loss}%  avg_rtt={flood_rtt}ms")
    else:
        # Fallback: Python flood + a during-flood ping sample. Can confirm the
        # flood had an effect, but can't fully characterise rate-limiting.
        out.append("## high-rate flood (engine: python ICMP fallback — hping3 not installed)")
        py_result = {}
        th = threading.Thread(target=_py_icmp_flood,
                              args=(target, FLOOD_SECONDS, py_result), daemon=True)
        th.start()
        try:
            dp = subprocess.run(["ping", "-c", str(BASELINE_COUNT), target],
                                capture_output=True, text=True,
                                timeout=BASELINE_COUNT + 15, stdin=subprocess.DEVNULL)
            flood_loss = _parse_loss(dp.stdout)
            flood_rtt = _parse_rtt_avg(dp.stdout)
            flood_txt = dp.stdout
            out.append(dp.stdout.strip())
        finally:
            th.join(FLOOD_SECONDS + 5)
        if py_result.get("error"):
            out.append(f"python flood error: {py_result['error']}")
            out.append(
                "FLOOD-PRIV-ERROR: the Python ICMP fallback could not send — "
                "unprivileged ICMP is disabled and we're not root. Fix ONE of: "
                "(a) install hping3 (sudo apt install hping3); (b) run as root; or "
                "(c) sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'.")
            return "\n".join(out)
        out.append(f"python flood: sent {py_result.get('sent', 0)} ICMP echoes via "
                   f"{py_result.get('mode', '?')}; during-flood loss={flood_loss}%")

    # ---- verdict: differential between normal-rate and high-rate ICMP ---------
    if flood_loss is None:
        out.append("[INCONCLUSIVE] could not parse the flood's delivery ratio — review raw log.")
        return "\n".join(out)

    base_ok = base_loss is not None and base_loss <= LOW_LOSS
    delta = (flood_loss - base_loss) if base_loss is not None else None
    inflated = (base_rtt and flood_rtt and base_rtt > 0
                and flood_rtt / base_rtt >= RTT_INFLATION
                and flood_rtt >= RTT_ABS_FLOOR)   # absolute floor: ignore LAN queueing

    if base_ok and delta is not None and delta >= RATE_LIMIT_DELTA:
        out.append(
            f"BLOCKED-RATELIMIT: normal-rate ICMP loss {base_loss:.1f}% but the "
            f"high-rate flood lost {flood_loss:.1f}% (+{delta:.0f} pts) — the boundary "
            "rate-limited/dropped the flood while letting ordinary pings through "
            "(classic ICMP rate-limit / DoS protection — control held).")
    elif base_ok and inflated:
        out.append(
            f"BLOCKED-RATELIMIT: the flood was delivered but its RTT inflated to "
            f"{flood_rtt:.0f}ms vs {base_rtt:.1f}ms baseline ({flood_rtt / base_rtt:.1f}x, "
            f">= {RTT_ABS_FLOOR:.0f}ms) — the boundary shaped/throttled the high-rate "
            "ICMP (policing — control held).")
    elif flood_loss <= LOW_LOSS:
        out.append(
            f"PASS: the high-rate ICMP flood was delivered end-to-end "
            f"({flood_loss:.1f}% loss over {FLOOD_COUNT} packets @ ~{FLOOD_PPS} pps"
            + (f", {FLOOD_SIZE}B payload" if FLOOD_SIZE else "") + ") — the boundary did "
            "NOT DROP this flood (it may only ALERT: detection != prevention). Enable "
            "anti-DoS PREVENTION/blocking, and crank HARNESS_ICMP_PPS / HARNESS_ICMP_SIZE "
            "/ HARNESS_ICMP_SECONDS to find the drop threshold or confirm it never drops.")
    elif not base_ok:
        # Baseline ICMP is (near-)100% lost, so there's no normal-vs-flood
        # differential. Rather than dead-end at INCONCLUSIVE, let the TEST decide:
        # if the host's TCP stack ANSWERS (open or RST), the host is UP and
        # reachable, so ICMP dropped end-to-end is a real BLOCK (ICMP filtered by
        # the boundary/host — control held), not an unreachable host. If TCP can't
        # confirm it's up (all silent), stay INCONCLUSIVE — it may be down, or the
        # source may have just been quarantined by the flood. No posture/policy
        # reliance — the verdict is from what the probes observed (ORG2026-70).
        up, how = _host_up_via_tcp(target, ctx) if base_loss is not None else (False, None)
        if up:
            out.append(
                f"BLOCKED-ICMP-FILTERED: normal-rate ICMP lost {base_loss:.0f}% and the flood "
                f"{flood_loss:.0f}%, but the host is confirmed UP via {how} — ICMP is dropped/"
                "filtered end-to-end while TCP passes, so the boundary/host BLOCKS ICMP "
                "(control held). A real block, not an unreachable host.")
        else:
            out.append(
                f"[INCONCLUSIVE] even normal-rate ICMP lost {base_loss}% and TCP liveness "
                "couldn't confirm the host is up (no port answered) — can't separate a down/"
                "unreachable host (or a source the flood just got quarantined) from ICMP "
                f"filtered entirely, so the {flood_loss:.1f}% flood loss isn't a clean "
                "rate-limit signal. Review raw log.")
    else:
        out.append(
            f"[INCONCLUSIVE] flood {flood_loss:.1f}% loss vs {base_loss}% baseline — "
            "ambiguous (could be boundary rate-limiting OR insufficient single-host "
            "load to fill the pipe). Review raw log.")
    return "\n".join(out)
