"""CVE-2021-44228 — Log4Shell. Confirms a JNDI-reachable target is up
(Solr on :8080), matching the manual test script exactly — an HTTP-code
reachability check, not a live JNDI callback exploit."""
import os

META = {
    "id": "log4shell",
    "name": "Log4Shell (CVE-2021-44228)",
    "category": "Server Exploitation",
    "control": "IPS signature (JNDI pattern)",
    "fix": "SD-WAN",
    "requires": ["curl"],
    "ports": [("tcp", 8080)],
    "success_regex": r"HTTP_CODE:200",
    "blocked_regex": r"timed out|Connection refused|HTTP_CODE:000",
}


def run(target, ctx):
    # os.devnull is /dev/null on POSIX and NUL on Windows — keeps this
    # cross-platform (the harness framework runs on any OS).
    return ctx.run_cmd(
        f'curl -s -m8 -o {os.devnull} -w "HTTP_CODE:%{{{{http_code}}}}" '
        '"http://{target}:8080/solr/"', target)
