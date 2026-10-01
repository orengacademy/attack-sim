"""Family C — TLS fingerprint mimicry (JA3/JA4).

Tool/implant TLS stacks have distinctive ClientHello fingerprints (JA3/JA4). If the
boundary blocks on fingerprint alone, an implant that mimics a browser's ClientHello
slips through. This module completes two handshakes to the same destination on 443:
one with the default (tool-like) TLS config, one shaped to look browser-like
(browser cipher order + ALPN h2/http1.1). If the browser-like hello succeeds where
policy should inspect, fingerprint-only detection is insufficient — behavioural NDR
is needed. Reported as a control observation (both handshakes' outcomes).

Destination: target:443 by default, or attacker_vps. NON-DESTRUCTIVE.
MITRE T1573 (Encrypted Channel).
"""
import ssl
from modules import _util as U

META = {
    "id": "ja3_mimicry",
    "name": "TLS Fingerprint Mimicry (JA3/JA4)",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "C",
    "direction": "a2b",
    "added": True,
    "control": "Behavioural NDR beyond TLS fingerprints; TLS inspection",
    "fix": "SD-WAN",
    "mitre": ["T1573"],
    "tactic": "Command and Control",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [("tcp", 443)],
    "port_customizable": True,
    "success_regex": r"^MIMIC-OK",
    "blocked_regex": r"both handshakes blocked|mimicry blocked",
}

# a browser-ish cipher preference order (OpenSSL names) — approximates a Chrome hello
_BROWSER_CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                    "ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256")


def _handshake(host, port, ctx, browser_like):
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if browser_like:
        try:
            c.set_ciphers(_BROWSER_CIPHERS)
            c.set_alpn_protocols(["h2", "http/1.1"])
        except (ssl.SSLError, NotImplementedError):
            pass
    try:
        with U.connect(host, port, ctx, timeout=8) as raw:
            with c.wrap_socket(raw, server_hostname=host) as t:
                return True, f"{t.version()} / {t.cipher()[0]}"
    except ssl.SSLError as e:
        return False, f"TLS error ({e.__class__.__name__})"
    except (OSError, Exception) as e:
        return False, f"{e.__class__.__name__}"


def run(target, ctx):
    host = ctx.cfg("attacker_vps") or target
    port = ctx.get_port("ja3_mimicry", 443)
    out = [f"# TLS fingerprint mimicry test vs {host}:{port} (Family C)"]
    d_ok, d_det = _handshake(host, port, ctx, browser_like=False)
    b_ok, b_det = _handshake(host, port, ctx, browser_like=True)
    out.append(f"default (tool-like) ClientHello : {'OK' if d_ok else 'blocked'} — {d_det}")
    out.append(f"browser-like ClientHello        : {'OK' if b_ok else 'blocked'} — {b_det}")
    out.append("")
    if b_ok and not d_ok:
        out.append("MIMIC-OK — the browser-like ClientHello succeeded where the tool-like "
                   "one was blocked: the boundary is filtering on TLS fingerprint and can "
                   "be evaded by mimicry (utls). [FINDING] behavioural NDR needed.")
    elif b_ok:
        out.append("MIMIC-OK — TLS to the destination completes (both hellos); if this "
                   "path should be inspected, fingerprint-based tool detection would not "
                   "stop a mimicked implant here. Verify against NDR.")
    else:
        out.append("both handshakes blocked — TLS to this destination is stopped "
                   "(inspection/egress control holding)")
    return "\n".join(out)
