"""Family A — Domain fronting / SNI-vs-Host mismatch.

Domain fronting hides the real destination by putting an innocent, high-reputation
CDN domain in the TLS SNI while the HTTP Host header (inside the encrypted session)
points at the real back-end on the same CDN. A boundary that filters on SNI only
is defeated. This module completes TLS with SNI = front_domain, then sends an HTTP
request with Host = front_host, and reports whether the mismatched request was
served — i.e. whether TLS inspection reads the true Host or the SNI is trusted.

Needs config: front_domain (CCN edge to put in SNI) + front_host (real Host behind
it) — both must be infrastructure you control/are authorised to front. Without them
it degrades to an ECH/SNI-visibility note (SKIP). NON-DESTRUCTIVE: one request.
MITRE T1090.004 (Domain Fronting).
"""
import ssl
from modules import _util as U

META = {
    "id": "domain_fronting",
    "name": "Domain Fronting / SNI≠Host",
    "category": "Egress / C2",
    "test_type": "attack_sim",
    "family": "A",
    "direction": "a2b",
    "added": True,
    "active": False,
    "control": "TLS inspection reads true Host (not SNI-only filtering)",
    "fix": "SD-WAN",
    "mitre": ["T1090.004"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [],
    "success_regex": r"^FRONTED ",
    "blocked_regex": r"fronting blocked",
}


def run(target, ctx):
    front = ctx.cfg("front_domain")
    host = ctx.cfg("front_host")
    out = [f"# domain-fronting test — SNI={front or '(unset)'} Host={host or '(unset)'}"]
    if not front or not host:
        out.append(U.skip("front_domain / front_host not configured (config.json) — "
                          "cannot run the fronting test. Note: also verify TLS "
                          "inspection + ECH policy manually where SNI is hidden."))
        return "\n".join(out)

    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        raw = U.connect(front, 443, ctx, timeout=8)
    except OSError as e:
        out.append(f"fronting blocked — could not reach front {front}:443 ({e.__class__.__name__})")
        return "\n".join(out)
    try:
        with c.wrap_socket(raw, server_hostname=front) as tls:
            req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: MyGovNet-USS/frontcheck\r\nConnection: close\r\n\r\n")
            tls.sendall(req.encode())
            data = tls.recv(512).decode(errors="replace")
            status_line = data.splitlines()[0] if data else "(no response)"
            parts = status_line.split()
            code = int(parts[1]) if (len(parts) >= 2 and parts[0].startswith("HTTP/")
                                     and parts[1].isdigit()) else 0
            out.append(f"SNI={front}  ->  Host={host}  first line: {status_line!r}")
            # Only a SERVED response (2xx/3xx) proves the mismatched Host reached the
            # back-end. A CDN that rejects the SNI≠Host mismatch answers 4xx/5xx
            # (commonly 403/421) — that is the front being BLOCKED, not fronted. The
            # old check fired on any 'HTTP/' line, scoring a 421 reject as FRONTED.
            if 200 <= code < 400:
                out.append(f"FRONTED SNI≠Host request was served ({code}) — the boundary "
                           f"filtered on SNI ({front}) only; the true Host ({host}) reached "
                           "the back-end. TLS inspection is not reading the real Host.")
            elif code >= 400:
                out.append(f"fronting blocked — the CDN/front rejected the mismatched Host "
                           f"({code}); SNI≠Host was not served.")
            else:
                out.append("fronting blocked — no HTTP response to the mismatched Host "
                           "(inspection or CDN rejected it)")
    except ssl.SSLError as e:
        out.append(f"fronting blocked — TLS error ({e.__class__.__name__}) "
                   "(possible TLS-inspection substitution)")
    except (OSError, Exception) as e:
        out.append(f"fronting blocked — {e.__class__.__name__}: {e}")
    finally:
        try:
            raw.close()
        except Exception:
            pass
    return "\n".join(out)
