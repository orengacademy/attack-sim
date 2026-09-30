"""SNMP community check. Matches the manual test script: a single snmpwalk
against the default 'public' community, not a wordlist brute force."""
META = {
    "id": "snmp_brute",
    "name": "SNMP Community Brute",
    "category": "Network Exploitation",
    "control": "Default-credential / community-string hygiene",
    "fix": "SD-WAN",
    "success_regex": r"STRING|INTEGER|OID",
    "blocked_regex": r"Timeout|No Response|timed out",
}


def run(target, ctx):
    return ctx.run_cmd("snmpwalk -v2c -c public -t5 {target}", target)
