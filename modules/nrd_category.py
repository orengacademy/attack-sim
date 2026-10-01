"""Family C — reputation / category laundering (newly-registered & uncategorised).

C2 is often hosted on a newly-registered domain (NRD) or an uncategorised
cloud-fronted host that URL-category / reputation filtering hasn't classified yet.
This module reaches YOUR attacker_domain (which should be new/uncategorised for the
engagement) on 443 and reports whether egress to an uncategorised destination is
permitted. Reachable = NRD/uncategorised filtering is not enforced = a finding.

Config: attacker_domain (a domain you registered/control for the test).
NON-DESTRUCTIVE (one HTTPS GET). MITRE T1090.002 / T1583.001.
"""
import ssl
from modules import _util as U

META = {
    "id": "nrd_category",
    "name": "NRD / Uncategorised-domain Egress",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "C",
    "direction": "a2b",
    "added": True,
    "control": "Block newly-registered / uncategorised destinations (443)",
    "fix": "SD-WAN",
    "mitre": ["T1090.002", "T1583.001"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [],
    "success_regex": r"^UNCATEGORISED-REACHABLE",
    "blocked_regex": r"uncategorised egress blocked",
}


def run(target, ctx):
    dom = ctx.cfg("attacker_domain")
    out = ["# NRD / uncategorised-domain egress test (Family C)"]
    if not dom:
        out.append(U.skip("attacker_domain not configured — need a newly-registered / "
                          "uncategorised domain you control to test category filtering."))
        return "\n".join(out)
    ok, detail = U.tls_reachable(dom, 443, ctx)
    out.append(f"{dom}:443 — {'reachable' if ok else 'blocked'} ({detail})")
    if ok:
        # fetch a byte to confirm HTTP flows, not just TLS
        try:
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            with U.connect(dom, 443, ctx, timeout=8) as raw:
                with c.wrap_socket(raw, server_hostname=dom) as t:
                    t.sendall(f"HEAD / HTTP/1.1\r\nHost: {dom}\r\nConnection: close\r\n\r\n".encode())
                    line = t.recv(128).decode(errors="replace").splitlines()
                    out.append(f"HTTP: {line[0] if line else '(no response)'}")
        except Exception as e:
            out.append(f"HTTP probe: {e.__class__.__name__}")
        out.append(f"UNCATEGORISED-REACHABLE — egress to your uncategorised domain {dom} is "
                   "permitted; newly-registered/uncategorised-destination filtering is not "
                   "enforced. [FINDING] C2 could be laundered behind an NRD.")
    else:
        out.append("uncategorised egress blocked — NRD/category filtering holding")
    return "\n".join(out)
