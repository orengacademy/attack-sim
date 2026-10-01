"""Family G — malleable C2 beacon shaping (NDR beacon-analytics test overlay).

Family G is a realism overlay: instead of a one-shot probe, this generates a
SUSTAINED, jittered beacon to a destination on 443 over a short window, shaped to
look like periodic web traffic (small GETs, randomised sleep). It exercises the NDR
/ UEBA beacon-detection stack — the thing a single connection can never test. The
verdict here is about whether the beacon *established and ran*; whether the SOC
*detected the periodicity* is recorded via the DETECTED path (detections.json).

ACTIVE (--active) only — it runs for beacon_seconds. Destination: attacker_vps or
canary_url host. NON-DESTRUCTIVE (tiny GETs). MITRE T1071.001 / T1573.
"""
import ssl
import time
import random
from urllib.parse import urlparse
from modules import _util as U

META = {
    "id": "beacon_shaping",
    "name": "Malleable C2 Beacon Shaping",
    "category": "Egress / C2",
    "test_type": "attack_sim",
    "family": "G",
    "direction": "a2b",
    "added": True,
    "active": True,
    "control": "Statistical beacon detection (NDR) tolerant of jitter; UEBA",
    "fix": "SD-WAN",
    "mitre": ["T1071.001", "T1573"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [],
    "success_regex": r"^BEACON-RAN",
    "blocked_regex": r"beacon blocked",
}


def _dest(ctx):
    if ctx.cfg("attacker_vps"):
        return ctx.cfg("attacker_vps"), 443, "/"
    url = ctx.cfg("canary_url")
    if url:
        u = urlparse(url if "://" in url else "https://" + url)
        return u.hostname, (u.port or 443), (u.path or "/")
    return None, None, None


def _callback(host, port, path, ctx):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 "
           "(Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: close\r\n\r\n")
    try:
        raw = U.connect(host, port, ctx, timeout=6)
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with c.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(req.encode())
            tls.recv(32)
        return True
    except Exception:
        return False


def run(target, ctx):
    host, port, path = _dest(ctx)
    out = ["# malleable C2 beacon-shaping test (Family G)"]
    if not host:
        out.append(U.skip("no attacker_vps / canary_url configured — nowhere to beacon."))
        return "\n".join(out)
    if not ctx.allow_active:
        ok, det = U.tls_reachable(host, port, ctx)
        out.append(f"indicator: {host}:{port} TLS {'reachable' if ok else 'blocked'} ({det})")
        out.append(U.skip("--active not set — not running a sustained beacon. Re-run with "
                          "--active to exercise NDR beacon analytics over a window."))
        return "\n".join(out)

    window = int(ctx.cfg("beacon_seconds", 60) or 60)
    interval = int(ctx.cfg("beacon_interval", 5) or 5)
    out.append(f"[ACTIVE] beaconing to {host}:{port} for ~{window}s, ~{interval}s jittered "
               "sleep, browser-like UA …")
    sent = ok = 0
    t0 = time.time()
    while time.time() - t0 < window:
        sent += 1
        if _callback(host, port, path, ctx):
            ok += 1
        # jitter: interval +/- 40%
        time.sleep(max(1, interval + random.uniform(-0.4, 0.4) * interval))
    out.append(f"callbacks: {ok}/{sent} succeeded over {int(time.time()-t0)}s")
    if ok:
        out.append(f"BEACON-RAN — a jittered beacon completed {ok} callbacks to {host} over "
                   "443. Now confirm with the SOC whether NDR/UEBA flagged the periodicity; "
                   "if it did, add this id to detections.json (scores DETECTED). If not, it "
                   "is a passed-undetected finding.")
    else:
        out.append("beacon blocked — no callbacks succeeded (egress to the beacon dest blocked)")
    return "\n".join(out)
