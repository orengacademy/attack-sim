"""Family F — WAF evasion on a published 443 app.

Validates the WAF ruleset in front of a published DC app (NOT the app itself): it
sends a canonical, HARMLESS detection string (an <script>alert(1)</script> probe)
plainly, then in encoding/case/double-encoding variants, and compares the responses.
If the plain probe is blocked (403/406) but an encoded variant is served (200), the
WAF normalises inconsistently and is evadable — a finding.

SAFE: benign XSS *marker* only (alert(1)); no real exploitation, one GET per variant.
Config: published_app_url (else target:443). MITRE T1190.
"""
import ssl
from urllib.parse import urlparse, quote
from modules import _util as U

META = {
    "id": "waf_evasion",
    "name": "WAF Evasion (published 443 app)",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "F",
    "direction": "a2b",
    "added": True,
    "control": "Normalising WAF; anomaly scoring; virtual patching",
    "fix": "Agency (WAF)",
    "mitre": ["T1190"],
    "tactic": "Initial Access",
    "cwe": ["CWE-20"],
    "requires": [],
    "ports": [("tcp", 443)],
    "port_customizable": True,
    "success_regex": r"^WAF-EVADED",
    "blocked_regex": r"WAF blocked all variants|unreachable",
}

_XSS = "<script>alert(1)</script>"
_VARIANTS = [
    ("plain", _XSS),
    ("url-encoded", quote(_XSS)),
    ("double-encoded", quote(quote(_XSS))),
    ("case-varied", "<ScRiPt>alert(1)</ScRiPt>"),
    ("param-pollution", f"q={_XSS}&q=benign"),
]


def _get(host, port, path, ctx):
    """(status_code:int|None) for a GET; None on transport failure."""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MyGovNet-USS/waf\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n")
    try:
        raw = U.connect(host, port, ctx, timeout=8)
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with c.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(req.encode())
            line = tls.recv(64).decode(errors="replace").splitlines()
        if line and line[0].startswith("HTTP/"):
            parts = line[0].split()
            return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    except Exception:
        return None
    return None


def run(target, ctx):
    url = ctx.cfg("published_app_url")
    if url:
        u = urlparse(url if "://" in url else "https://" + url)
        host, port, base = u.hostname, (u.port or 443), (u.path or "/")
    else:
        host, port, base = target, ctx.get_port("waf_evasion", 443), "/"
    out = [f"# WAF evasion test vs {host}:{port}{base} (Family F)"]
    sep = "&" if "?" in base else "?"
    results = {}
    for label, payload in _VARIANTS:
        path = f"{base}{sep}q={payload}" if "=" not in payload else f"{base}{sep}{payload}"
        code = _get(host, port, path, ctx)
        results[label] = code
        out.append(f"  {label:<16} -> {code if code is not None else 'no response/blocked'}")
    plain = results.get("plain")
    served = [k for k, v in results.items() if k != "plain" and v == 200]
    out.append("")
    if plain in (403, 406, 501) and served:
        out.append(f"WAF-EVADED — the plain probe was blocked ({plain}) but variant(s) "
                   f"{served} were served (200): the WAF normalises inconsistently and is "
                   "evadable. [FINDING]")
    elif all(v in (403, 406, 501) or v is None for v in results.values()):
        out.append("WAF blocked all variants — normalising WAF holding (or app unreachable)")
    else:
        out.append("REVIEW — WAF did not clearly block the plain probe; confirm the target "
                   "is WAF-fronted and whether these should be blocked.")
    return "\n".join(out)
