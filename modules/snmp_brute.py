"""SNMP community check. Matches the manual test script: a single snmpwalk
against the default 'public' community, not a wordlist brute force."""
META = {
    "id": "snmp_brute",
    "name": "SNMP Community Brute",
    "category": "Network Exploitation",
    "control": "Default-credential / community-string hygiene",
    "fix": "SD-WAN",
    "mitre": ['T1110.001'],
    "cwe": ['CWE-1392'],
    "tactic": 'Credential Access',
    "requires": ["snmpwalk"],
    "ports": [("udp", 161)],
    "success_regex": r"STRING|INTEGER|OID",
    "blocked_regex": r"Timeout|No Response|timed out",
}


def run(target, ctx):
    # -r1 (1 retry) so a filtered/closed UDP 161 resolves in ~6s instead of the
    # default ~30s (5 retries x timeout) — snmpwalk is otherwise the long pole.
    return ctx.run_cmd("snmpwalk -v2c -c public -t3 -r1 {target}", target)
