"""Family D — reverse / server-initiated egress (B -> A / B -> out).

The "and vice versa" half of the brief and the direction least often locked down:
a KVDC/IPDC *server* should rarely initiate outbound to the internet or user zones.
Run this FROM a data-centre foothold (use --source <DC interface IP>, or run the
harness on the DC host) — it attempts server-initiated outbound connections on the
ports a reverse shell / beacon would use. Any that succeed = server-initiated
egress is not default-denied = a finding.

Destinations: attacker_vps (preferred) or public IPs. NON-DESTRUCTIVE (connects,
sends nothing). MITRE T1571 / T1090.
"""
from modules import _util as U

# ports a reverse shell / beacon / update-check would try outbound from a server
_EGRESS_PORTS = [443, 80, 53, 22, 8080, 8443, 4444, 9001]
_PUBLIC = ["1.1.1.1", "8.8.8.8"]

META = {
    "id": "reverse_egress",
    "name": "Reverse / Server-initiated Egress (B->A/out)",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "direction": "b2a",
    "added": True,
    "control": "Default-deny server-initiated egress (DC VLAN)",
    "fix": "SD-WAN",
    "mitre": ["T1571", "T1090"],
    "tactic": "Command and Control",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [],
    "success_regex": r"^EGRESS-OPEN",
    "blocked_regex": r"server egress blocked",
}


def run(target, ctx):
    vps = ctx.cfg("attacker_vps")
    out = ["# reverse / server-initiated egress test (Family D, B->A/out)",
           f"# run from a DC foothold; source bind = {ctx.source_ip or 'OS default route'}"]
    open_ports = []
    if vps:
        out.append(f"# destination: attacker_vps {vps}")
        for p in _EGRESS_PORTS:
            st = U.tcp_state(vps, p, ctx, timeout=5)
            out.append(f"  {vps}:{p}/tcp — {st}")
            if st == "open":
                open_ports.append(f"{p}->{vps}")
    else:
        out.append("# no attacker_vps set — probing public IPs on key egress ports")
        for host in _PUBLIC:
            for p in (443, 80, 53):
                st = U.tcp_state(host, p, ctx, timeout=5)
                out.append(f"  {host}:{p}/tcp — {st}")
                if st == "open":
                    open_ports.append(f"{p}->{host}")
    out.append("")
    if open_ports:
        out.append(f"EGRESS-OPEN — server-initiated outbound permitted on: "
                   f"{', '.join(open_ports)}. [FINDING] a DC host can beacon / reverse-shell "
                   "out; server-VLAN egress is not default-denied (the weakest direction).")
    else:
        out.append("server egress blocked — no server-initiated outbound got through "
                   "(default-deny on the DC egress path holding)")
    return "\n".join(out)
