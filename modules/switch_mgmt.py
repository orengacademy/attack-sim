"""Family D — network-device (switch/router) management-plane exposure.

Validates that switch/router MANAGEMENT is not reachable across the A<->B boundary.
It probes the device management ports (SSH 22, Telnet 23, HTTP/HTTPS 80/443, SNMP
161, syslog 514, NTP 123, NETCONF 830) plus Cisco Smart Install (4786 — a well-known
switch-takeover vector) on the target (or config "switch_targets"). Any reachable
management service across zones = a segmentation gap on the network fabric itself.

Note: full VLAN-hopping (DTP/trunk negotiation, 802.1Q double-tagging) needs L2
adjacency at the site switch and cannot be tested remotely — flagged for the on-site
LAN-analysis step. NON-DESTRUCTIVE (reachability only). MITRE T1046 / T1078.
"""
from modules import _util as U

_TCP = [(22, "SSH"), (23, "Telnet"), (80, "HTTP"), (443, "HTTPS"),
        (830, "NETCONF"), (4786, "Cisco-SmartInstall"), (8291, "MikroTik-Winbox")]
_UDP = [(161, "SNMP"), (514, "syslog"), (123, "NTP")]

META = {
    "id": "switch_mgmt",
    "name": "Switch/Router Mgmt-plane Exposure",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "direction": "both",
    "added": True,
    "control": "No device management reachable across zones (mgmt VRF isolated)",
    "fix": "SD-WAN",
    "mitre": ["T1046", "T1078"],
    "tactic": "Discovery",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [],
    "success_regex": r"^MGMT-EXPOSED",
    "blocked_regex": r"no mgmt-plane exposure",
}


def run(target, ctx):
    targets = ctx.cfg("switch_targets", []) or [target]
    if isinstance(targets, str):
        targets = [targets]
    out = ["# switch/router management-plane exposure (Family D)"]
    exposed = []
    for host in targets:
        out.append(f"# device: {host}")
        for port, name in _TCP:
            st = U.tcp_state(host, port, ctx, timeout=3)
            out.append(f"  {port}/{name} — {st}")
            if st == "open":
                exposed.append(f"{host}:{port}/{name}")
        for port, name in _UDP:
            st = U.udp_egress(host, port, ctx, timeout=3)
            out.append(f"  {port}/{name} (udp) — {st}")
            if st == "reply":
                exposed.append(f"{host}:{port}/{name}")
    out.append("")
    out.append("# NOTE: VLAN-hopping (DTP/double-tag) needs on-site L2 adjacency — cover "
               "it in the LAN-analysis step, not remotely.")
    if exposed:
        out.append(f"MGMT-EXPOSED — device management reachable across the boundary: "
                   f"{', '.join(exposed)}. [FINDING] the management plane is not isolated "
                   "to a dedicated VRF/segment (Cisco Smart Install / Winbox especially).")
    else:
        out.append("no mgmt-plane exposure — device management not reachable across zones")
    return "\n".join(out)
