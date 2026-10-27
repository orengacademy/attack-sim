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
import socket
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
                return True, f"{t.version()} / {t.cipher()[0]}", "ok"
    except ssl.SSLError as e:
        return False, f"TLS error ({e.__class__.__name__})", "tls"
    except socket.timeout:
        return False, "timed out", "timeout"
    except ConnectionResetError:
        return False, "reset by peer", "reset"
    except ConnectionRefusedError:
        return False, "refused (no listener — egress reached the endpoint)", "refused"
    except socket.gaierror:
        return False, "DNS did not resolve", "dns"
    except OSError as e:
        return False, f"{e.__class__.__name__}", "other"


def run(target, ctx):
    host = ctx.cfg("attacker_vps") or target
    port = ctx.get_port("ja3_mimicry", 443)
    out = [f"# TLS fingerprint mimicry test vs {host}:{port} (Family C)"]
    d_ok, d_det, d_kind = _handshake(host, port, ctx, browser_like=False)
    b_ok, b_det, b_kind = _handshake(host, port, ctx, browser_like=True)
    out.append(f"default (tool-like) ClientHello : {'OK' if d_ok else 'blocked'} — {d_det}")
    out.append(f"browser-like ClientHello        : {'OK' if b_ok else 'blocked'} — {b_det}")
    out.append("")
    if b_ok and not d_ok:
        out.append("MIMIC-OK — the browser-like ClientHello succeeded where the tool-like "
                   "one was blocked: the boundary is filtering on TLS fingerprint and can "
                   "be evaded by mimicry (utls). [FINDING] behavioural NDR needed.")
    elif b_ok:
        # BOTH hellos completed -> no TLS-fingerprint discrimination is in path, so no
        # evasion was demonstrated. The old code scored this MIMIC-OK (a false finding on
        # any reachable 443). It's indeterminate, not a finding.
        out.append("[INCONCLUSIVE] both the tool-like and browser-like ClientHellos completed — "
                   "no TLS-fingerprint discrimination is in path on this destination, so mimicry "
                   "evasion cannot be demonstrated here (NOT a finding). Point at a destination "
                   "behind fingerprint-based inspection, or verify against NDR.")
    else:
        kinds = {d_kind, b_kind}
        if kinds <= {"refused"}:
            # Both handshakes got a RST at connect: the SYN REACHED the endpoint (egress
            # traversed) and it has no TLS listener — a tester-setup gap, NOT the boundary
            # stopping TLS. Scoring it "both handshakes blocked" (BLOCKED) would credit an
            # egress control that let the traffic through. Skip.
            out.append("[SKIP] both handshakes were REFUSED (RST) — the endpoint has no TLS "
                       f"listener on {port} and egress REACHED it (traversed), so this is NOT a "
                       "boundary block. Point at a live TLS endpoint / your VPS's 443.")
        elif "dns" in kinds:
            out.append("[SKIP] the destination did not resolve from THIS SOURCE (resolver/DNS "
                       "artifact, not the target's egress control) — can't assess TLS mimicry "
                       "from here. Fix the source resolver or pass an IP.")
        else:
            out.append("both handshakes blocked — TLS to this destination is stopped "
                       "(timed out / reset / filtered in transit — inspection/egress control holding)")
    return "\n".join(out)
