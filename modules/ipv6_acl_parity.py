"""Family D — IPv6 ACL parity.

Dual-stack boundaries frequently enforce IPv4 ACLs but leave IPv6 wide open (or
vice versa). This repeats a small sensitive-port check over IPv6 so a gap in ACL
parity surfaces. Any sensitive port reachable over IPv6 (that IPv4 policy would
block) is a finding.

Needs an IPv6 target: pass an IPv6 literal as the target, set config
"ipv6_target", or a hostname that resolves to AAAA. NON-DESTRUCTIVE sockets.
MITRE T1599 (Network Boundary Bridging) / T1046.
"""
import socket

_PORTS = [(22, "SSH"), (445, "SMB"), (3389, "RDP"), (3306, "MySQL"),
          (1433, "MSSQL"), (5985, "WinRM"), (389, "LDAP"), (443, "HTTPS")]

META = {
    "id": "ipv6_acl_parity",
    "name": "IPv6 ACL Parity Sweep",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "direction": "a2b",
    "added": True,
    "control": "IPv6 ACLs mirror IPv4 (deny by default on both stacks)",
    "fix": "SD-WAN",
    "mitre": ["T1599", "T1046"],
    "tactic": "Discovery",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [],
    "success_regex": r"^IPV6-OPEN",
    "blocked_regex": r"no IPv6 target|no sensitive IPv6 ports reachable",
}


def _resolve_v6(host, cfg_target):
    if cfg_target:
        host = cfg_target
    try:                                   # already an IPv6 literal?
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6)
        return infos[0][4][0] if infos else None
    except socket.gaierror:
        return None


def _probe6(addr, port, ctx, timeout=4):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if ctx.source_ip and ":" in ctx.source_ip:
            try:
                s.bind((ctx.source_ip, 0))
            except OSError:
                pass
        s.connect((addr, port))
        return "open"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "unreachable"
    finally:
        s.close()


def run(target, ctx):
    addr = _resolve_v6(target, ctx.cfg("ipv6_target"))
    out = ["# IPv6 ACL parity sweep (Family D)"]
    if not addr:
        out.append("no IPv6 target — pass an IPv6 literal as target, set config "
                   "ipv6_target, or use a host with an AAAA record. [SKIP]")
        return "\n".join(out)
    out.append(f"# IPv6 target: {addr}")
    opened = []
    for port, name in _PORTS:
        st = _probe6(addr, port, ctx)
        out.append(f"  [{addr}]:{port}/{name} — {st}")
        if st == "open":
            opened.append(f"{port}/{name}")
    out.append("")
    if opened:
        out.append(f"IPV6-OPEN — sensitive port(s) reachable over IPv6: {', '.join(opened)}. "
                   "[FINDING] confirm IPv4 policy blocks these — an IPv6 ACL gap bridges the "
                   "boundary the IPv4 rules protect.")
    else:
        out.append("no sensitive IPv6 ports reachable — IPv6 ACL parity holding")
    return "\n".join(out)
