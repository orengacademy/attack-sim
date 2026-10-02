"""Struts2 OGNL injection (CVE-2017-5638) — ZERO-config IPS/WAF signature test.

Maps directly to a capability the target appliance advertises: Sangfor's NGWAF
lists "struts2 injection" and deserialization defense explicitly, so this grades
whether that signature actually fires. The classic CVE-2017-5638 vector is an
OGNL expression in the HTTP Content-Type header — an inline WAF/IPS inspects
request headers, so sending the pattern is enough to exercise the signature (no
creds, no infra, no vulnerable Struts app needed — nothing executes; the OGNL
pattern on the wire is what the signature matches).

Verdict: the payload-bearing request reached the app (served) -> the WAF/IPS did
NOT filter the Struts2 signature (finding); reset / empty reply / 403 / 406 ->
an inline control blocked it.
"""
import re

META = {
    "id": "struts2_ognl",
    "name": "Struts2 OGNL Injection (CVE-2017-5638)",
    "category": "Server Exploitation",
    "test_type": "pentest",
    "added": True,
    "control": "IPS/WAF signature (Struts2 OGNL / Content-Type)",
    "fix": "SD-WAN",
    "cve": "CVE-2017-5638",
    "mitre": ['T1190'],
    "cwe": ['CWE-917'],
    "tactic": 'Initial Access',
    "requires": ["curl"],
    "ports": [("tcp", 80)],
    "port_customizable": True,
    "success_regex": r"^\[STRUTS2-DELIVERED\]",
    "blocked_regex": (r"^\[STRUTS2-BLOCKED\]|Connection reset|Empty reply from server|"
                      r"Recv failure|curl: \((52|56|104)\)"),
}

# The CVE-2017-5638 signature: an OGNL expression in Content-Type (benign — a
# harmless `echo`, not a real command; the point is the pattern the WAF matches).
# Braces doubled so ctx.run_cmd's .format() passes them through literally.
_CT = ("%{{(#nike='multipart/form-data').(#cmd='STRUTS2-PROBE')."
       "(#a=@java.lang.Runtime@getRuntime()).(#a.exec(#cmd))}}")
_PATHS = ["/", "/index.action", "/struts2-showcase/", "/upload.action"]
_BLOCK = re.compile(r"Connection reset|Empty reply from server|Recv failure|curl: \((52|56|104)\)",
                    re.IGNORECASE)


def run(target, ctx):
    port = ctx.get_port("struts2_ognl", 80)
    out = [f"# Struts2 OGNL (CVE-2017-5638) IPS/WAF signature test vs {target}:{port}", ""]
    delivered, blocked = [], []
    for p in _PATHS:
        cmd = (f'curl -s -S -m8 -o /dev/null -H "Content-Type: {_CT}" '
               f'-w "HTTP_CODE:%{{{{http_code}}}}" "http://{{target}}:{port}{p}"')
        raw = ctx.run_cmd(cmd, target)
        out += [f"## Content-Type OGNL -> {p}", raw, ""]
        m = re.search(r"HTTP_CODE:(\d{3})", raw)
        code = m.group(1) if m else "000"
        if code in ("000", "403", "406") or _BLOCK.search(raw):
            blocked.append(p)
        else:
            delivered.append(f"{p} [{code}]")
    out.append("")
    if delivered:
        out.append(f"[STRUTS2-DELIVERED] the OGNL Content-Type reached the app on "
                   f"{len(delivered)}/{len(_PATHS)} path(s) — the WAF/IPS did NOT filter the "
                   "CVE-2017-5638 signature (finding): " + "; ".join(delivered))
    else:
        out.append("[STRUTS2-BLOCKED] every OGNL request was blocked/reset — the WAF/IPS "
                   "filtered the Struts2 signature.")
    return "\n".join(out)
