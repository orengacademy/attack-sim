"""FTP anonymous login check. Matches the manual test script's curl test,
with -v added so a real FTP "230 Login successful" is visible even when
the directory listing itself is empty (empty stdout would otherwise look
identical to a rejected login)."""
META = {
    "id": "ftp_anonymous",
    "name": "FTP Anonymous Login",
    "category": "Network Exploitation",
    "test_type": "va",
    "control": "Anonymous access hardening",
    "fix": "Server",
    "mitre": ['T1078.001'],
    "cwe": ['CWE-306'],
    "tactic": 'Initial Access',
    "requires": ["curl"],
    "ports": [("tcp", 21)],
    "port_customizable": True,
    "success_regex": r"230 Login successful|230 User logged in|230 Anonymous",
    # Added the mid-session RESET signatures: an IPS/WAF (e.g. Sangfor's FTP-anonymous
    # signature) typically lets the TCP connect + 220 banner through, then RESETS the
    # session the instant it sees `USER anonymous` -> curl prints "Recv failure:
    # Connection reset by peer". That is the control working (BLOCKED), but it used to
    # match nothing here and fell through to NO-RESULT. ^FTP-BLOCKED is the module's
    # own explicit marker (below).
    "blocked_regex": (r"530|Login incorrect|Access denied|timed out|Connection refused|"
                      r"Connection reset|reset by peer|Recv failure|^FTP-BLOCKED"),
}


def run(target, ctx):
    port = ctx.get_port("ftp_anonymous", 21)   # overridable per-attack (GUI/env)
    raw = ctx.run_cmd(
        f'curl -s -v -m8 "ftp://anonymous:anonymous@{{target}}:{port}/"', target)
    import re
    # 230 = anonymous login ACCEPTED (the finding) — success_regex decides; leave as-is.
    if re.search(r"\b230\b", raw):
        return raw
    # Banner (220) received but the session was RESET / torn down before a 230 success
    # => the anonymous login was refused MID-EXCHANGE. On this lab that's the appliance's
    # FTP-anonymous IPS resetting `USER anonymous` (or host hardening). Make it an
    # explicit BLOCKED so a reset isn't a mute NO-RESULT. (A plain closed/refused port
    # with no banner stays NO-SERVICE via recon — this only fires once the service
    # answered, i.e. it IS there and the login specifically was cut.)
    if re.search(r"\b220\b", raw) and re.search(
            r"reset by peer|Recv failure|Connection reset|\b5\d\d\b|Login incorrect|Access denied",
            raw, re.I):
        raw += ("\n\nFTP-BLOCKED: the FTP banner (220) came back but the anonymous login was "
                "RESET/denied before any 230 success — anonymous access is blocked (server "
                "hardening, or the appliance's FTP-anonymous IPS reset the `USER anonymous` "
                "session). Control works.")
    return raw
