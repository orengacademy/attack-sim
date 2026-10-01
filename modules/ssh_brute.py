"""SSH credential check via hydra. Matches the manual test script: a
single known username/password (core.DEFAULT_CREDENTIALS), not a
wordlist brute force — this validates whether that credential works and
whether repeated auth attempts get rate-limited/blocked upstream."""
META = {
    "id": "ssh_brute",
    "name": "SSH Brute Force",
    "category": "Network Exploitation",
    "test_type": "va",
    "control": "Brute-force protection / rate-limit",
    "fix": "SD-WAN",
    "mitre": ['T1110.001'],
    "cwe": ['CWE-307'],
    "tactic": 'Credential Access',
    "requires": ["hydra"],
    "serial": True,   # rate-limit test: run alone so it isn't skewed
    "ports": [("tcp", 22)],
    "port_customizable": True,
    # hydra's own success line looks like "login: X   password: Y"
    "success_regex": r"login:.*password:",
    "blocked_regex": r"timed out|Connection refused|No route",
}


def run(target, ctx):
    port = ctx.get_port("ssh_brute", 22)   # overridable per-attack (GUI/env)
    # This is a single known-credential check, not a wordlist brute. With no
    # password configured, hydra would run with an empty -p and complete cleanly
    # as "0 valid passwords found" — which matches neither success nor blocked
    # regex and mis-reports as NO-RESULT. Skip instead, with a clear reason.
    if not (ctx.creds.get("dc_pass") or "").strip():
        return (f"# ssh_brute vs {target}\n\n[SKIP] no SSH password configured "
                "(set HARNESS_DC_PASS or credentials.env) — nothing to test. "
                "deploy/setup_target.sh writes a credentials.env for the lab user.")
    return ctx.run_cmd(
        f"hydra -s {port} -l {{dc_user}} -p {{dc_pass}} -f ssh://{{target}}", target)
