"""Family B — DNS-over-TLS (TCP/853) and DNS-over-QUIC (UDP/853) egress.

A quick default-deny check: is the non-standard DNS-encryption port 853 quietly
open outbound? DoT (TCP/853) and DoQ (UDP/853) let an endpoint reach an external
encrypted resolver, bypassing internal DNS. Any 853 egress = a finding.

Uses a public DoT/DoQ resolver by default (Cloudflare 1.1.1.1 / Quad9) or your
attacker_vps. NON-DESTRUCTIVE. MITRE T1071.004.
"""
from modules import _util as U

# public DoT/DoQ endpoints on 853
_DOT_HOSTS = ["1.1.1.1", "9.9.9.9"]

META = {
    "id": "dot_doq_853",
    "name": "DoT/DoQ Egress (853)",
    "category": "Network Exploitation",
    "test_type": "attack_sim",
    "family": "B",
    "direction": "a2b",
    "added": True,
    "control": "Default-deny egress ports (853 not permitted outbound)",
    "fix": "SD-WAN",
    "mitre": ["T1071.004"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [("tcp", 853), ("udp", 853)],
    "success_regex": r"^853-OPEN",
    "blocked_regex": r"853 egress blocked",
}


def run(target, ctx):
    vps = ctx.cfg("attacker_vps")
    hosts = [vps] if vps else _DOT_HOSTS
    out = ["# DoT/DoQ (853) egress test (Family B)"]
    findings = []
    for host in hosts:
        # DoT = TLS on TCP/853
        ok, detail = U.tls_reachable(host, 853, ctx, timeout=5)
        out.append(f"DoT  {host}:853/tcp — {'reachable' if ok else 'blocked'} ({detail})")
        if ok:
            findings.append(f"DoT {host}")
        # DoQ = QUIC on UDP/853 (best-effort datagram)
        st = U.udp_egress(host, 853, ctx, timeout=4)
        out.append(f"DoQ  {host}:853/udp — {st}")
        if st == "reply":
            findings.append(f"DoQ {host}")
    out.append("")
    if findings:
        out.append(f"853-OPEN — encrypted-DNS egress on 853 permitted: {', '.join(findings)}. "
                   "[FINDING] a non-standard port is open outbound; default-deny egress "
                   "not enforced.")
    else:
        out.append("853 egress blocked — DoT/DoQ on 853 not permitted (default-deny holding)")
    return "\n".join(out)
