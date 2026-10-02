"""Family B — direct plaintext DNS (UDP/53) to an EXTERNAL resolver.

The most basic DNS-egress control question: can an endpoint talk plaintext DNS
straight to a public resolver (8.8.8.8) instead of being forced through the
internal resolver? If a query to the external resolver is answered, outbound 53 is
not restricted to internal resolvers — DNS logging/sinkholing is bypassed and DNS
tunnelling to an external authoritative NS becomes possible. Finding.

Pure-socket (no dig dependency), honours ctx.source_ip. Config: external_resolver
(default 8.8.8.8). MITRE T1071.004 / T1048.001.
"""
from modules import _util as U

META = {
    "id": "dns_egress_external",
    "name": "External DNS Egress (UDP/53 to public resolver)",
    "category": "Network Exploitation",
    "test_type": "attack_sim",
    "family": "B",
    "direction": "a2b",
    "added": True,
    "control": "Restrict outbound 53 to internal resolvers only",
    "fix": "SD-WAN",
    "mitre": ["T1071.004", "T1048.001"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [("udp", 53)],
    "success_regex": r"^EXTERNAL-DNS-OK",
    "blocked_regex": r"external DNS blocked",
}


def run(target, ctx):
    resolver = ctx.cfg("external_resolver", "8.8.8.8")
    out = [f"# external DNS egress test — {resolver}:53/udp (Family B)"]
    # UDP/53 has no handshake, so a single lost packet would falsely read as
    # "blocked". Try up to 3 times — a one-off loss self-heals; a real block fails
    # all — so the verdict is consistent run-to-run.
    egressed, detail = False, "no response"
    for _ in range(3):
        egressed, detail = U.dns_query("example.com", resolver, ctx, timeout=4)
        if egressed:
            break
    out.append(f"query example.com @ {resolver} — {detail}")
    if egressed:
        out.append(f"EXTERNAL-DNS-OK — plaintext DNS to the external resolver {resolver} "
                   "was answered; outbound 53 is NOT forced to the internal resolver. "
                   "[FINDING] DNS logging/sinkholing bypassable; DNS tunnelling possible.")
    else:
        out.append("external DNS blocked — outbound 53 to the public resolver did not "
                   "succeed (forced internal resolver holding)")
    return "\n".join(out)
