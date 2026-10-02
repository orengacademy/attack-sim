"""Web IPS/WAF signature battery — ZERO-config IPS-practice check.

The appliance's IPS/WAF either catches common web-attack signatures or it
doesn't. This fires a battery of well-known, benign-but-recognisable attack
patterns at the target's web port and reports which ones REACHED the app vs were
blocked/reset by an inline IPS/WAF. No creds, no config, no attacker infra —
just curl to an open HTTP port — so it's a drop-in way to grade the appliance's
web-signature coverage (same class as apache_41773 / log4shell, broadened).

Each probe is a classic signature an IPS/WAF is expected to know:
Shellshock, SQLi, reflected XSS, command injection, LFI, encoded traversal,
known-bad scanner URIs (w00tw00t / webshell / .env), and scanner User-Agents
(sqlmap / Nikto). Verdict: ANY probe delivered end-to-end => the IPS has a GAP
(finding); ALL blocked/reset => the IPS caught them (control held).

Payloads are URL-encoded (no shell metachars reach a shell — ctx.run_cmd never
uses a shell), and the one brace-bearing payload (Shellshock) is doubled so
ctx.run_cmd's .format() passes it through literally. Nothing executes on the
target; the POINT is the signature pattern on the wire, not RCE.
"""
import re

META = {
    "id": "web_ips_sigs",
    "name": "Web IPS/WAF Signature Battery",
    "category": "Server Exploitation",
    "test_type": "attack_sim",
    "family": "D",
    "added": True,
    "control": "IPS/WAF web-attack signatures",
    "fix": "SD-WAN",
    "mitre": ['T1190', 'T1059'],
    "cwe": ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-22'],
    "tactic": 'Initial Access',
    "requires": ["curl"],
    "ports": [("tcp", 80)],
    "port_customizable": True,
    # delivered at least one signature -> IPS gap (finding)
    "success_regex": r"^\[IPS-GAP\]",
    # the appliance caught/reset them all -> control held
    "blocked_regex": r"^\[IPS-CAUGHT-ALL\]|Connection reset|Empty reply from server|Recv failure",
}

# (label, extra curl args, path). Braces in the Shellshock UA are doubled for
# ctx.run_cmd's .format(); everything else is URL-encoded.
_SIGS = [
    ("Shellshock UA (CVE-2014-6271)", '-A "() {{ :; }}; echo ; /bin/cat /etc/passwd"', "/cgi-bin/"),
    ("SQL injection (OR 1=1)", "", "/?id=1%27%20OR%20%271%27%3D%271"),
    ("Reflected XSS", "", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("Command injection", "", "/?x=%3B%20cat%20%2Fetc%2Fpasswd"),
    ("Local File Include", "", "/?file=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
    ("Encoded path traversal", "", "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
    ("Scanner URI (w00tw00t)", "", "/w00tw00t.at.ISC.SANS.DFind%3A%29"),
    ("Webshell probe", "", "/shell.php?cmd=id"),
    ("Sensitive file (.env)", "", "/.env"),
    ("Scanner UA (sqlmap)", '-A "sqlmap/1.5#stable (http://sqlmap.org)"', "/"),
    ("Scanner UA (Nikto)", '-A "Mozilla/5.00 (Nikto/2.1.6)"', "/"),
]
_BLOCK = re.compile(r"Connection reset|Empty reply from server|Recv failure|curl: \((52|56|104)\)",
                    re.IGNORECASE)


def run(target, ctx):
    port = ctx.get_port("web_ips_sigs", 80)
    out = [f"# Web IPS/WAF signature battery vs {target}:{port} "
           f"({len(_SIGS)} signatures, zero-config)", ""]
    delivered, blocked = [], []
    for label, extra, path in _SIGS:
        cmd = (f'curl -s -S -m8 -o /dev/null {extra} '
               f'-w "SIG HTTP_CODE:%{{{{http_code}}}}" "http://{{target}}:{port}{path}"')
        raw = ctx.run_cmd(cmd, target)
        out += [f"## {label}  ->  {path}", raw, ""]
        m = re.search(r"HTTP_CODE:(\d{3})", raw)
        code = m.group(1) if m else "000"
        # 403/406/000 or a reset = the inline IPS/WAF stopped it; any other HTTP
        # response = the payload reached the app (signature not filtered).
        if code in ("000", "403", "406") or _BLOCK.search(raw):
            blocked.append(label)
        else:
            delivered.append(f"{label} [{code}]")

    out.append("")
    if delivered:
        out.append(f"[IPS-GAP] {len(delivered)}/{len(_SIGS)} web-attack signature(s) reached the "
                   "app — the IPS/WAF did NOT filter them (finding): " + "; ".join(delivered))
        if blocked:
            out.append(f"  (blocked {len(blocked)}: " + ", ".join(blocked) + ")")
    else:
        out.append(f"[IPS-CAUGHT-ALL] all {len(_SIGS)} web-attack signatures were blocked/reset "
                   "by an inline IPS/WAF — web-signature control held.")
    return "\n".join(out)
