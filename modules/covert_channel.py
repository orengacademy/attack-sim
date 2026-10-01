"""Covert-channel / tunneling test (A -> B). Checks whether two out-of-band
channels are open through the SD-WAN:

  * ICMP  — ping with a data payload; if echo replies return carrying the data,
    ICMP can ferry arbitrary bytes (a viable covert channel / exfil path).
  * DNS   — a uniquely-labelled query under HARNESS_DNS_ZONE (default
    example.com) via the system resolver; if it egresses, DNS to arbitrary
    domains is permitted (the precondition for DNS tunnelling).

Honest scope: full exfil PROOF needs an authoritative server you control for
the zone. This module tests the SD-WAN control question — is the channel open
at all. Linux (uses `ping -p` and `dig`); no root required.
"""
import os
import uuid
import subprocess

ZONE = os.environ.get("HARNESS_DNS_ZONE", "example.com")
PAYLOAD_HEX = "657866696c7465737400"   # "exfiltest\0"

META = {
    "id": "covert_channel",
    "name": "Covert Channel (ICMP/DNS tunneling)",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "E",
    "added": True,   # added after the initial harness set
    "control": "Covert-channel / DNS-egress control",
    "fix": "SD-WAN",
    "mitre": ['T1572', 'T1048.003'],
    "cwe": ['CWE-693'],
    "tactic": 'Exfiltration',
    "requires": ["ping", "dig"],
    "os_supported": ["Linux"],   # ping -p / dig flags are Linux-shaped
    "ports": [("icmp", None)],
    "success_regex": r"^CHANNEL-OPEN ",
    "blocked_regex": r"no covert channel open",
}


def run(target, ctx):
    out = [f"# covert-channel / tunneling test vs {target}"]
    open_ch = []

    # --- ICMP data payload ---
    try:
        p = subprocess.run(["ping", "-c", "3", "-p", PAYLOAD_HEX, target],
                           capture_output=True, text=True, timeout=15)
        replied = "bytes from" in p.stdout and " 0 received" not in p.stdout
        if replied:
            out.append("CHANNEL-OPEN ICMP — echo replies returned with data "
                       "payload (covert channel viable)")
            open_ch.append("ICMP")
        else:
            out.append("ICMP: no usable replies (channel not open)")
    except FileNotFoundError:
        out.append("[ERROR] ping not found")
    except Exception as e:
        out.append(f"ICMP: error {e}")

    # --- DNS egress / tunnelling precondition ---
    # HONEST SCOPE: proving DNS tunnelling needs a zone you are AUTHORITATIVE for —
    # then a query for a unique label under it reaching your NS is the real signal.
    # Querying a zone you DON'T control (the old default example.com) is useless:
    # a recursive resolver answers NXDOMAIN for a random example.com label, which
    # only proves "DNS resolves", not "arbitrary-domain egress / tunnelling". So we
    # only claim a channel when an operator zone is configured.
    cfg_zone = ctx.cfg("canary_dns_zone") or ctx.cfg("attacker_domain")
    zone = cfg_zone or ZONE
    # "operator-controlled" = a zone was set in config.json, OR HARNESS_DNS_ZONE was
    # pointed at something other than the useless example.com default.
    operator_controlled = bool(cfg_zone) or ZONE != "example.com"
    label = f"exfil-{uuid.uuid4().hex[:12]}.{zone}"
    try:
        d = subprocess.run(["dig", "+time=3", "+tries=1", label],
                           capture_output=True, text=True, timeout=10)
        resolved = ("ANSWER SECTION" in d.stdout
                    or "status: NXDOMAIN" in d.stdout
                    or "status: NOERROR" in d.stdout)
        if not operator_controlled:
            out.append(f"DNS: queried {label} ({'answered' if resolved else 'no answer'}) — "
                       "INDICATOR ONLY: no attacker-controlled zone configured "
                       "(set canary_dns_zone / attacker_domain). A reply for a random "
                       "label under a zone you don't own only shows DNS works, NOT "
                       "tunnelling, so this is not scored as a covert channel.")
        elif resolved:
            out.append(f"CHANNEL-OPEN DNS — a query for {label} (your zone) egressed "
                       "toward your authoritative NS (DNS-tunnel precondition met)")
            open_ch.append("DNS")
        else:
            out.append(f"DNS: query under your zone did not egress/resolve ({label})")
    except FileNotFoundError:
        out.append("[ERROR] dig not found (install dnsutils)")
    except Exception as e:
        out.append(f"DNS: error {e}")

    out.append("")
    if open_ch:
        out.append("[FINDING] covert channel(s) open A->B: " + ", ".join(open_ch))
    else:
        out.append("no covert channel open")
    return "\n".join(out)
