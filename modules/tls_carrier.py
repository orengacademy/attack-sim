"""TLS carrier on 443 — completes a TLS handshake and reads the peer cert.
Confirms 443 is a usable encrypted carrier that tunnels/C2 (Cloudflare Tunnel,
ngrok, chisel, many C2s) ride on, and reveals a TLS-inspecting proxy substituting
its own cert. Adapted from additional/mygovnet_egress_probe.py (test_tls).
"""
import socket
import ssl

META = {
    "id": "tls_carrier",
    "name": "TLS Carrier (443)",
    "category": "Application Control",
    "added": True,
    "control": "TLS egress / C2 carrier on 443",
    "fix": "SD-WAN",
    "mitre": ["T1071.001"],
    "tactic": "Command and Control",
    "cwe": [],
    "requires": [],
    "ports": [("tcp", 443)],
    "port_customizable": True,
    "success_regex": r"^TLS-OK",
    "blocked_regex": r"timed out|refused|no-tls|unreachable",
}


def run(target, ctx):
    port = ctx.get_port("tls_carrier", 443)
    out = [f"# TLS carrier test vs {target}:{port}"]
    ctxs = ssl.create_default_context()
    ctxs.check_hostname = False
    ctxs.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target, port), timeout=8) as raw:
            with ctxs.wrap_socket(raw, server_hostname=str(target)) as tls:
                ver = tls.version()
                cert = tls.getpeercert(binary_form=True) or b""
                out.append(f"TLS-OK {ver} established — 443 is a usable encrypted "
                           f"carrier (cert {len(cert)}B; inspect for proxy substitution)")
    except ssl.SSLError as e:
        out.append(f"no-tls: SSL error ({e})")
    except (socket.timeout, TimeoutError):
        out.append("timed out")
    except ConnectionRefusedError:
        out.append("refused")
    except socket.gaierror:
        out.append("unreachable: name did not resolve")
    except OSError as e:
        out.append(f"unreachable: {e}")
    return "\n".join(out)
