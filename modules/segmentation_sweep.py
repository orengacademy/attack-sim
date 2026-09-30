"""Segmentation sweep (A -> B). Checks a broad set of sensitive management /
database / lateral-movement ports and reports which are reachable through the
SD-WAN. Every reachable port is a segmentation gap the policy permits — the #1
question for an agency-to-KVDC/cloud SD-WAN. Pure sockets: no external tools,
no root, runs on any OS. Advisory recon is separate; this module IS the check,
so its own output is the evidence.
"""
import socket

# (port, label) — sensitive services that generally should NOT be reachable
# straight from an agency network to a data-centre / cloud target.
SENSITIVE = [
    (135, "MSRPC"), (139, "NetBIOS-SSN"), (445, "SMB"),
    (3389, "RDP"), (5985, "WinRM-HTTP"), (5986, "WinRM-HTTPS"),
    (1433, "MSSQL"), (3306, "MySQL"), (5432, "PostgreSQL"), (1521, "Oracle"),
    (636, "LDAPS"), (3268, "GlobalCatalog"), (3269, "GlobalCatalog-SSL"),
    (5900, "VNC"), (6379, "Redis"), (27017, "MongoDB"),
    (9200, "Elasticsearch"), (11211, "memcached"), (2375, "Docker-API"),
]
TIMEOUT = 1.5

META = {
    "id": "segmentation_sweep",
    "name": "Segmentation Sweep (mgmt/DB/lateral ports)",
    "category": "Segmentation",
    "control": "Network segmentation / firewall policy (A->B)",
    "fix": "SD-WAN",
    "requires": [],
    "ports": [],   # this module performs its own sweep; recon would duplicate it
    # a reachable sensitive port = segmentation GAP = attack "passed"
    "success_regex": r"^OPEN ",
    "blocked_regex": r"no sensitive ports reachable",
}


def _probe(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return "OPEN"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except socket.gaierror:
        return "unresolved"
    except OSError:
        return "unreachable"


def run(target, ctx):
    out = [f"# segmentation sweep vs {target} ({len(SENSITIVE)} sensitive ports)"]
    opened = []
    for port, name in SENSITIVE:
        st = _probe(target, port)
        if st == "OPEN":
            opened.append(f"{port}/{name}")
            out.append(f"OPEN {port}/tcp ({name})")
        else:
            out.append(f"{st} {port}/tcp ({name})")
    out.append("")
    if opened:
        out.append(f"[FINDING] {len(opened)} sensitive port(s) reachable A->B "
                   f"(segmentation gap): " + ", ".join(opened))
    else:
        out.append("no sensitive ports reachable (segmentation holding)")
    return "\n".join(out)
