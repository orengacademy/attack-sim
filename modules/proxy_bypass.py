"""Family C — direct-to-internet egress (authenticated-proxy bypass).

If all egress is supposed to traverse an (authenticated) proxy, then a host should
NOT be able to open a direct TCP/443 session to the internet. This module tries a
DIRECT connection (ignoring any configured system proxy) to a public host / your
attacker_vps on 443. If it connects directly, there is a proxy-bypass egress path —
a beacon can go direct-to-internet without honouring the proxy. Finding.

Reports any system proxy env vars for context. NON-DESTRUCTIVE. MITRE T1090.
"""
import os
from modules import _util as U

_PUBLIC = ["1.1.1.1", "8.8.8.8"]

META = {
    "id": "proxy_bypass",
    "name": "Direct-to-internet Egress (proxy bypass)",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "C",
    "direction": "a2b",
    "added": True,
    "control": "Enforce authenticated proxy for all egress (no direct path)",
    "fix": "SD-WAN",
    "mitre": ["T1090"],
    "tactic": "Command and Control",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [],
    "success_regex": r"^DIRECT-EGRESS",
    "blocked_regex": r"no direct egress path",
}


def run(target, ctx):
    out = ["# direct-to-internet egress / proxy-bypass test (Family C)"]
    proxies = {k: v for k, v in os.environ.items()
               if k.lower() in ("http_proxy", "https_proxy", "all_proxy")}
    out.append(f"system proxy env: {proxies or 'none set'}")
    vps = ctx.cfg("attacker_vps")
    dests = ([vps] if vps else []) + _PUBLIC
    direct = []
    for host in dests:
        # tcp_state / tls do NOT use any proxy — they are raw sockets, so a success
        # here is a genuine direct path regardless of the configured proxy.
        st = U.tcp_state(host, 443, ctx, timeout=6)
        out.append(f"direct TCP/443 to {host} — {st}")
        if st == "open":
            direct.append(host)
    out.append("")
    if direct:
        out.append(f"DIRECT-EGRESS — direct (non-proxied) TCP/443 reached: {', '.join(direct)}. "
                   "[FINDING] there is a direct-to-internet path that bypasses the proxy; a "
                   "beacon need not honour the authenticated proxy.")
    else:
        out.append("no direct egress path — direct TCP/443 to the internet is blocked "
                   "(egress forced via proxy — good)")
    return "\n".join(out)
