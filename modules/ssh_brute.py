"""SSH credential check via hydra. Matches the manual test script: a
single known username/password (core.DEFAULT_CREDENTIALS), not a
wordlist brute force — this validates whether that credential works and
whether repeated auth attempts get rate-limited/blocked upstream."""
META = {
    "id": "ssh_brute",
    "name": "SSH Brute Force",
    "category": "Network Exploitation",
    "control": "Brute-force protection / rate-limit",
    "fix": "SD-WAN",
    # hydra's own success line looks like "login: X   password: Y"
    "success_regex": r"login:.*password:",
    "blocked_regex": r"timed out|Connection refused|No route",
}


def run(target, ctx):
    return ctx.run_cmd(
        "hydra -l {dc_user} -p {dc_pass} -f ssh://{target}", target)
