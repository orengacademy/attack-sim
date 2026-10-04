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
    connected = False   # at least one TCP flow actually established
    reset = False       # at least one established flow was RESET (L7 enforcing)
    for port, payload, label in PAIRS:
        try:
            s = socket.create_connection((target, port), timeout=TIMEOUT)
            connected = True
        except (socket.timeout, TimeoutError):
            out.append(f"{label}: no connect (filtered) — port blocked")
            continue
        except ConnectionRefusedError:
            out.append(f"{label}: Connection refused — port closed (service absent)")
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
        except (ConnectionResetError, BrokenPipeError) as e:
            # the App-ID / firewall RESET the mismatched flow — the control WORKING.
            # Without this, the reset propagated out of run() -> recorded as a module
            # crash (NO-RESULT) instead of a block.
            reset = True
            out.append(f"{label}: {e.__class__.__name__} — the mismatched protocol was "
                       "reset (App-ID/L7 enforcing, good)")
        except OSError as e:
            out.append(f"{label}: send/recv error ({e.__class__.__name__})")
        finally:
            s.close()
    out.append("")
    if allowed:
        out.append("[FINDING] SD-WAN is port-based (App-ID not enforcing L7) for: "
                   + ", ".join(allowed))
    elif connected:
        # a flow WAS established but no mismatch got through (reset/no reply) — this
        # is the control (App-ID/L7) actually doing its job.
        out.append("no mismatch allowed (App-ID or firewall enforcing L7)"
                   + (" — mismatched flows reset" if reset else ""))
    else:
        # nothing connected at all: the ports are closed/filtered, so there is no
        # service to mismatch — this must NOT be credited to L7 enforcement (it
        # would be a false BLOCKED). No blocked_regex marker here on purpose.
        out.append("no ports reachable — service absent / ports closed "
                   "(NOT an App-ID/L7 enforcement result)")
    return "\n".join(out)
