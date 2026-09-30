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
    return ctx.run_cmd(
        f"hydra -s {port} -l {{dc_user}} -p {{dc_pass}} -f ssh://{{target}}", target)
