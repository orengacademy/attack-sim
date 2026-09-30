"""Application-ID / protocol-port mismatch (A -> B). Sends a deliberately WRONG
L7 protocol into an allowed port (SSH banner into an HTTP port, HTTP request
into the SSH port). If the flow establishes and bytes move, the SD-WAN is
enforcing by PORT only, not by application identity — i.e. App-ID is not
catching the mismatch, which is a policy-bypass finding.

Caveat (honest): establishing the flow shows the mismatched protocol was NOT
blocked at the SD-WAN; a definitive App-ID verdict for a specific app also
wants a service listening on a non-standard port on B. This is the client-side
indicator. Pure sockets, no external tools, any OS.
"""
import socket

# (port, payload-to-send, label) — a protocol that does NOT match the port.
PAIRS = [
    (80,   b"SSH-2.0-AppIDEvasionTest\r\n",            "SSH-banner-into-HTTP(80)"),
    (8080, b"SSH-2.0-AppIDEvasionTest\r\n",            "SSH-banner-into-HTTP(8080)"),
    (22,   b"GET / HTTP/1.0\r\nHost: appid-test\r\n\r\n", "HTTP-request-into-SSH(22)"),
]
TIMEOUT = 4.0

META = {
    "id": "appid_port_mismatch",
    "name": "App-ID Protocol/Port Mismatch",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "D",
    "added": True,   # added after the initial harness set
    "control": "Application-ID / L7 policy (not port-based)",
    "fix": "SD-WAN",
    "mitre": ['T1571'],
    "cwe": ['CWE-923'],
    "tactic": 'Command and Control',
    "requires": [],
    "ports": [],
    # mismatch allowed = App-ID not enforcing = finding ("passed")
    "success_regex": r"^MISMATCH-ALLOWED ",
    "blocked_regex": r"no mismatch allowed",
}


def run(target, ctx):
    out = [f"# App-ID protocol/port-mismatch test vs {target}"]
    allowed = []
    for port, payload, label in PAIRS:
        try:
            s = socket.create_connection((target, port), timeout=TIMEOUT)
        except (socket.timeout, TimeoutError):
            out.append(f"{label}: no connect (filtered) — port blocked")
            continue
        except ConnectionRefusedError:
            out.append(f"{label}: refused — port closed")
            continue
        except OSError as e:
            out.append(f"{label}: connect error ({e.__class__.__name__})")
            continue
        try:
            s.sendall(payload)
            s.settimeout(TIMEOUT)
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            resp = data.decode(errors="replace").strip().replace("\n", " ")[:80]
            out.append(f"MISMATCH-ALLOWED {label} — flow established through the "
                       f"SD-WAN; resp: {resp!r}")
            allowed.append(label)
        finally:
            s.close()
    out.append("")
    if allowed:
        out.append("[FINDING] SD-WAN is port-based (App-ID not enforcing L7) for: "
                   + ", ".join(allowed))
    else:
        out.append("no mismatch allowed (App-ID or firewall enforcing L7)")
    return "\n".join(out)
