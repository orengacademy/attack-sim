"""CVE-2021-44228 — Log4Shell. Sends a BENIGN JNDI marker string in the
User-Agent and a header so the SD-WAN IPS's JNDI signature is actually
exercised (not just a reachability ping). The JNDI URL points at
127.0.0.1:1389 on the *target*, which has no attacker LDAP server, so there is
NO real callback and NO code execution even if the target is vulnerable — this
tests whether the pattern transits the IPS, which is the stated control.

Verdict: the payload-bearing request was served (any HTTP_CODE:2xx/3xx) -> it
reached the app layer and got a real response, so the IPS did NOT filter the
JNDI pattern (finding) — a 3xx redirect still means the backend processed the
request (headers included), same conclusion as a 200; curl's own exit/timeout
code (via HTTP_CODE:000) or an explicit 403 means something between us and the
app refused/dropped it. No/blocked response -> control held.
"""
import os

META = {
    "id": "log4shell",
    "name": "Log4Shell (CVE-2021-44228)",
    "category": "Server Exploitation",
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
    # was HTTP_CODE:200 only — a 3xx redirect (common for app servers/reverse
    # proxies on the target) fell through neither regex and showed as a
    # confusing NO-RESULT even though the payload-bearing request clearly
    # reached the app (confirmed: a lab target returning HTTP_CODE:302).
    "success_regex": r"HTTP_CODE:[23]\d\d",
    "blocked_regex": r"timed out|Connection refused|HTTP_CODE:000|HTTP_CODE:403",
}

# doubled braces survive ctx.run_cmd's .format(); collapse to single at runtime.
# non-routable target-local LDAP URL => signature test only, never a callback.
_JNDI = "${{jndi:ldap://127.0.0.1:1389/log4shell-probe}}"


def run(target, ctx):
    port = ctx.get_port("log4shell", 8080)
    # -L: follow redirects instead of reporting the redirect's own 3xx. Some
    # apps on this port (e.g. Apache Solr — a real-world Log4Shell target —
    # redirects "/" -> "/solr/" unconditionally, regardless of payload) would
    # otherwise always show HTTP_CODE:302 no matter what; -L reports the
    # *actual* final response instead, which is what we care about (did the
    # payload-bearing request reach a real, served page).
    # %-format inserts devnull/payload/port (leaves {{ }} and {target} intact for
    # ctx.run_cmd's later .format); %% -> % ; %d -> port.
    tmpl = ('curl -s -m10 -L -o %s -A "%s" -H "X-Api-Version: %s" '
            '-w "HTTP_CODE:%%{{http_code}}" "http://{target}:%d/"') % (
                os.devnull, _JNDI, _JNDI, port)
    return ctx.run_cmd(tmpl, target)
