"""Family A — Encrypted C2 & tunnelling over 443 (egress domain allow-listing test).

NON-DESTRUCTIVE: it does NOT build a tunnel. It TLS-connects (443) to the broker
endpoints that cloudflared / ngrok / Dev Tunnels / localtunnel dial, and reports
which are reachable. A reachable broker = the boundary permits egress to tunnel
infrastructure (no category/domain allow-listing) = the precondition every 443
tunnel needs = a finding. All brokers blocked = egress allow-listing working.

Maps to plan Family A; control: egress domain allow-listing / category filtering /
app-ID. MITRE T1572 (Protocol Tunnelling) / T1071.001.
"""
import socket
import ssl

# (label, host) — the 443 endpoints these tunnel/remote-access services dial.
BROKERS = [
    ("cloudflared", "api.trycloudflare.com"),
    ("ngrok",       "connect.ngrok-agent.com"),
    ("devtunnels",  "global.rel.tunnels.api.visualstudio.com"),
    ("localtunnel", "localtunnel.me"),
    ("pinggy",      "a.pinggy.io"),
]
TIMEOUT = 6

META = {
    "id": "egress_tunnel_brokers",
    "name": "443 Tunnel-broker Egress (cloudflared/ngrok/…)",
    "category": "Egress / C2",
    "added": True,
    "test_type": "attack_sim",
    "family": "A",
    "control": "Egress domain allow-listing / tunnel-category filtering (443)",
    "fix": "SD-WAN",
    "mitre": ["T1572", "T1071.001"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [],          # egress test — not a target-port probe
    "success_regex": r"^REACHABLE ",
    "blocked_regex": r"all tunnel brokers blocked",
}


def _tls_ok(host):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True, "TLS established"
    except ssl.SSLError as e:
        return True, f"reached (TLS error {e.__class__.__name__})"  # egress still allowed
    except (socket.timeout, TimeoutError):
        return False, "timed out (blocked)"
    except socket.gaierror:
        return False, "DNS did not resolve (blocked/forced-resolver)"
    except OSError as e:
        return False, f"unreachable ({e.__class__.__name__})"


def run(target, ctx):
    # target is unused — this tests THIS host's egress through the SD-WAN, like
    # doh_bypass. Kept in the signature for interface consistency.
    out = ["# 443 tunnel-broker egress test (Family A — egress allow-listing)"]
    reachable = []
    for label, host in BROKERS:
        ok, detail = _tls_ok(host)
        if ok:
            reachable.append(label)
            out.append(f"REACHABLE {label} ({host}) — {detail}")
        else:
            out.append(f"blocked   {label} ({host}) — {detail}")
    out.append("")
    if reachable:
        out.append(f"[FINDING] tunnel-broker egress permitted to: {', '.join(reachable)} "
                   "— a 443 tunnel (cloudflared/ngrok/etc.) could establish; egress "
                   "domain allow-listing is not enforced.")
    else:
        out.append("all tunnel brokers blocked — egress allow-listing holding")
    return "\n".join(out)
