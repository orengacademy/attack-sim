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
    "requires": ["curl"],
    "ports": [("tcp", 21)],
    "success_regex": r"230 Login successful|230 User logged in|230 Anonymous",
    "blocked_regex": r"530|Login incorrect|Access denied|timed out|Connection refused",
}


def run(target, ctx):
    return ctx.run_cmd(
        'curl -s -v -m8 "ftp://anonymous:anonymous@{target}/"', target)
