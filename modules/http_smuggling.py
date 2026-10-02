"""Family C — HTTP request-smuggling / desync probe (safe, single-shot).

Tests whether the boundary reverse-proxy / load-balancer in front of published DC
apps parses HTTP consistently. It sends ONE request carrying BOTH a Content-Length
and a Transfer-Encoding: chunked header (the classic CL.TE ambiguity) on its OWN
connection and observes the response/timing. A 400/501 (rejected) means the proxy
normalises ambiguous framing (good); a timeout waiting for the "smuggled" body, or
a 200, suggests the front-end accepted ambiguous framing and may be desyncable.

SAFE: a single benign request on a dedicated connection — it does NOT poison a
shared connection or send a second victim request. Confirm a real desync manually
before reporting as exploitable. Config: published_app_url (or target:443).
MITRE T1190.
"""
import ssl
import socket
import time
from urllib.parse import urlparse
from modules import _util as U

META = {
    "id": "http_smuggling",
    "name": "HTTP Request Smuggling / Desync (probe)",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "C",
    "direction": "a2b",
    "added": True,
    "control": "Consistent HTTP parsing (reject ambiguous CL/TE)",
    "fix": "SD-WAN",
    "mitre": ["T1190"],
    "tactic": "Initial Access",
    "cwe": ["CWE-444"],
    "requires": [],
    "ports": [("tcp", 443)],
    "port_customizable": True,
    "success_regex": r"^DESYNC-SUSPECT",
    "blocked_regex": r"ambiguous framing rejected|unreachable|Connection reset|reset by peer|Broken pipe",
}


def run(target, ctx):
    url = ctx.cfg("published_app_url")
    if url:
        u = urlparse(url if "://" in url else "https://" + url)
        host = u.hostname
        port = u.port or (443 if u.scheme != "http" else 80)
        tls = u.scheme != "http"
        path = u.path or "/"
    else:
        host, port, tls, path = target, ctx.get_port("http_smuggling", 443), True, "/"
    out = [f"# HTTP smuggling/desync probe vs {host}:{port}{path} (Family C)"]

    # CL.TE: Content-Length says 6 bytes of body, but Transfer-Encoding: chunked
    # says the body ends at the "0" chunk. A consistent parser rejects this.
    body = "0\r\n\r\nG"   # chunked terminator + one stray byte
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
           "Connection: close\r\n\r\n" + body)
    try:
        raw = U.connect(host, port, ctx, timeout=8)
    except OSError as e:
        out.append(f"unreachable: {e.__class__.__name__}")
        return "\n".join(out)
    try:
        if tls:
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            sock = c.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        sock.sendall(req.encode())
        sock.settimeout(8)
        t0 = time.time()
        try:
            data = sock.recv(256).decode(errors="replace")
        except socket.timeout:
            data = ""
        dt = time.time() - t0
        first = data.splitlines()[0] if data else "(no response / timed out)"
        out.append(f"response: {first!r}  (after {dt:.1f}s)")
        if any(code in first for code in (" 400", " 501", " 411")):
            out.append("ambiguous framing rejected — the proxy normalises CL/TE "
                       "(consistent parsing — good)")
        elif not data or dt >= 7.5:
            out.append("DESYNC-SUSPECT — the front-end waited for more body (ambiguous "
                       "CL/TE not rejected); possible request-smuggling exposure. Verify "
                       "a real desync manually before reporting. [REVIEW/FINDING]")
        else:
            out.append(f"DESYNC-SUSPECT — server accepted ambiguous CL/TE framing "
                       f"({first!r}); confirm desync manually. [REVIEW/FINDING]")
    except ssl.SSLError as e:
        out.append(f"ambiguous framing rejected — TLS error ({e.__class__.__name__})")
    except Exception as e:
        out.append(f"probe error: {e.__class__.__name__}: {e}")
    finally:
        try:
            raw.close()
        except Exception:
            pass
    return "\n".join(out)
