"""Segmentation sweep (A -> B). Checks a broad set of sensitive management /
database / lateral-movement ports and reports which are reachable through the
SD-WAN. Every reachable port is a segmentation gap the policy permits — the #1
question for an agency-to-KVDC/cloud SD-WAN. Pure sockets: no external tools,
no root, runs on any OS. Advisory recon is separate; this module IS the check,
so its own output is the evidence.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# (port, label) — sensitive services that generally should NOT be reachable
# straight from an agency network to a data-centre / cloud target.
SENSITIVE = [
    # remote access / management
    (22, "SSH"), (23, "Telnet"), (830, "NETCONF"),
    (135, "MSRPC"), (139, "NetBIOS-SSN"), (445, "SMB"),
    (3389, "RDP"), (5985, "WinRM-HTTP"), (5986, "WinRM-HTTPS"),
    (5900, "VNC"), (2375, "Docker-API"),
    # directory / auth
    (88, "Kerberos"), (389, "LDAP"), (636, "LDAPS"),
    (3268, "GlobalCatalog"), (3269, "GlobalCatalog-SSL"),
    # databases
    (1433, "MSSQL"), (3306, "MySQL"), (5432, "PostgreSQL"), (1521, "Oracle"),
    (6379, "Redis"), (27017, "MongoDB"), (9200, "Elasticsearch"),
    (11211, "memcached"),
    # file / rpc / misc
    (111, "rpcbind"), (2049, "NFS"), (8080, "HTTP-alt"),
]
TIMEOUT = 1.5

META = {
    "id": "segmentation_sweep",
    "name": "Segmentation Sweep (mgmt/DB/lateral ports)",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "added": True,   # added after the initial harness set
    "control": "Network segmentation / firewall policy (A->B)",
    "fix": "SD-WAN",
    "mitre": ['T1046'],
    "cwe": ['CWE-923'],
    "tactic": 'Discovery',
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
    # probe in parallel so the sweep stays fast and bounded (~TIMEOUT total)
    # even when many ports are filtered (which each cost the full timeout).
    results = {}
    try:
        with ThreadPoolExecutor(max_workers=min(32, len(SENSITIVE) or 1)) as ex:
            futs = {ex.submit(_probe, target, port): (port, name)
                    for port, name in SENSITIVE}
            for f in as_completed(futs):
                port, name = futs[f]
                try:
                    results[port] = f.result()
                except Exception:
                    results[port] = "error"
    except Exception:
        # thread-pool unavailable for any reason -> fall back to sequential
        for port, name in SENSITIVE:
            results[port] = _probe(target, port)

    # A target that doesn't resolve makes EVERY port "unresolved" -> with no OPEN
    # ports the old code concluded "segmentation holding" (a false CONTROL-WORKING).
    # Flag it as an error instead so a typo'd/bad target isn't credited to the control.
    if results and all(v == "unresolved" for v in results.values()):
        out.append(f"[ERROR] target '{target}' did not resolve — cannot sweep "
                   "(this is NOT 'segmentation holding'; fix the target).")
        return "\n".join(out)

    opened = []
    for port, name in SENSITIVE:            # preserve declared order in output
        st = results.get(port, "error")
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
