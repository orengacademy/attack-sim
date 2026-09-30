"""Family A — UDP/443 (QUIC / HTTP-3) egress.

Cloudflare Tunnel and other modern tunnels prefer QUIC over UDP/443, and many
boundaries allow TCP/443 but forget UDP/443. This module sends a best-effort
datagram to UDP/443 (a public QUIC endpoint by default, or your attacker_vps) and
reports whether UDP/443 egress is permitted. Permitted UDP/443 = a QUIC tunnel
path the TCP rules don't cover = a finding; blocked = default-deny on UDP/443.

NON-DESTRUCTIVE: a single small datagram. MITRE T1572.
"""
from modules import _util as U

# public QUIC/HTTP-3 endpoints on UDP/443 (used when no attacker_vps is set)
_DEFAULT_QUIC = ["cloudflare-quic.com", "www.google.com"]

META = {
    "id": "udp443_quic",
    "name": "UDP/443 (QUIC) Egress",
    "category": "Egress / C2",
    "test_type": "attack_sim",
    "family": "A",
    "direction": "a2b",
    "added": True,
    "control": "Default-deny UDP/443 (QUIC) egress",
    "fix": "SD-WAN",
    "mitre": ["T1572"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [("udp", 443)],
    "success_regex": r"^UDP443-OPEN",
    "blocked_regex": r"UDP/443 egress blocked",
}

# a tiny QUIC-ish initial byte (long header form) — enough to elicit a reply from
# a real QUIC server without a full handshake; harmless if dropped.
_QUIC_PROBE = b"\xc0\x00\x00\x00\x01\x08" + b"\x00" * 18


def run(target, ctx):
    vps = ctx.cfg("attacker_vps")
    dests = [vps] if vps else _DEFAULT_QUIC
    out = ["# UDP/443 (QUIC) egress test (Family A)"]
    egress = []
    for host in dests:
        st = U.udp_egress(host, 443, ctx, payload=_QUIC_PROBE, timeout=4)
        out.append(f"{host}:443/udp — {st}")
        # 'reply' = definite; 'sent (no reply)' = the local stack egressed it
        # (UDP is connectionless; a boundary that dropped it would still show this,
        # so we treat a reply as strong and no-reply as "permitted for egress").
        if st in ("reply", "sent (no reply)"):
            egress.append(f"{host} ({st})")
    out.append("")
    if egress:
        out.append(f"UDP443-OPEN — UDP/443 egress permitted to: {', '.join(egress)}. "
                   "A QUIC tunnel (cloudflared) can use this path even if TCP/443 is "
                   "controlled. [FINDING if a 'reply' was seen; verify no-reply cases "
                   "against firewall logs — UDP has no handshake.]")
    else:
        out.append("UDP/443 egress blocked — datagrams refused/blocked (default-deny holding)")
    return "\n".join(out)
