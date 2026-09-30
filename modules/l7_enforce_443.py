"""L4-vs-L7 enforcement on 443 — sends deliberately NON-TLS bytes to 443. A
port-only firewall forwards anything on 443; an application-aware boundary should
reset a 443 session that isn't valid TLS. If the peer accepts/holds the non-TLS
session, the boundary is NOT enforcing L7 — exactly the gap raw-TCP tunnels
(chisel/gost) exploit. Adapted from additional/mygovnet_egress_probe.py (test_l7).
"""
import socket

META = {
    "id": "l7_enforce_443",
    "name": "L4-vs-L7 Enforcement (443)",
    "category": "Application Control",
    "added": True,
    "control": "Application-ID / L7 enforcement on 443",
    "fix": "SD-WAN",
    "mitre": ["T1095", "T1071.001"],
    "tactic": "Command and Control",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [("tcp", 443)],
    "port_customizable": True,
    # non-TLS tolerated on 443 = App-ID not enforcing = finding
    "success_regex": r"^L7-NOT-ENFORCED",
    "blocked_regex": r"L7-ENFORCED|reset|refused|timed out|unreachable",
}

_MARKER = b"MYGOVNET-EGRESS-PROBE/NON-TLS-L7-CHECK\r\n"


def run(target, ctx):
    port = ctx.get_port("l7_enforce_443", 443)
    out = [f"# L4-vs-L7 enforcement test vs {target}:{port}"]
    try:
        s = socket.create_connection((target, port), timeout=8)
    except (socket.timeout, TimeoutError):
        return "\n".join(out + ["timed out / filtered"])
    except ConnectionRefusedError:
        return "\n".join(out + ["refused (port closed)"])
    except OSError as e:
        return "\n".join(out + [f"unreachable: {e}"])
    try:
        s.sendall(_MARKER)
        s.settimeout(8)
        try:
            data = s.recv(64)
            out.append(f"L7-NOT-ENFORCED: peer answered non-TLS bytes on {port} "
                       f"({len(data)}B) — port-based only, tunnelable")
        except socket.timeout:
            out.append(f"L7-NOT-ENFORCED: non-TLS session held open on {port} "
                       "(no L7 reset) — tunnelable")
    except ConnectionResetError:
        out.append("L7-ENFORCED: reset on non-TLS bytes — App-ID/L7 enforced (good)")
    except OSError as e:
        out.append(f"unreachable: {e}")
    finally:
        s.close()
    return "\n".join(out)
