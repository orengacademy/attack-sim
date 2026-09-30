"""FTP anonymous login check. Matches the manual test script's curl test,
with -v added so a real FTP "230 Login successful" is visible even when
the directory listing itself is empty (empty stdout would otherwise look
identical to a rejected login)."""
META = {
    "id": "ftp_anonymous",
    "name": "FTP Anonymous Login",
    "category": "Network Exploitation",
    "control": "Anonymous access hardening",
    "fix": "Server",
    "mitre": ['T1078.001'],
    "cwe": ['CWE-306'],
    "tactic": 'Initial Access',
    "requires": ["curl"],
    "ports": [("tcp", 21)],
    "port_customizable": True,
    "success_regex": r"230 Login successful|230 User logged in|230 Anonymous",
    "blocked_regex": r"530|Login incorrect|Access denied|timed out|Connection refused",
}


def run(target, ctx):
    port = ctx.get_port("ftp_anonymous", 21)   # overridable per-attack (GUI/env)
    return ctx.run_cmd(
        f'curl -s -v -m8 "ftp://anonymous:anonymous@{{target}}:{port}/"', target)
