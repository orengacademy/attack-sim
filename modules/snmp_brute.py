"""SNMP community check. Matches the manual test script: a single walk
against the default 'public' community, not a wordlist brute force.

Uses snmpbulkwalk (GETBULK), not snmpwalk (one GETNEXT per OID). A
chatty target — routine for a Windows box: process list, TCP table,
interface stats, ... — can have a large enough MIB tree that walking it
one OID at a time takes minutes even with nothing wrong on the wire;
confirmed ~9-12x more throughput from switching to GETBULK against a lab
DC (a few hundred thousand bytes of MIB data), on top of the existing
-t3 -r1 fast-fail for a genuinely filtered/closed port. Packet loss on
the path (e.g. right after icmp_flood, which runs just before this
module and measurably degrades the link for a few seconds — see
modules/icmp_flood.py) makes the one-OID-at-a-time version even worse:
every dropped GETNEXT costs a full timeout+retry, and with hundreds of
OIDs a couple of drops alone adds minutes. GETBULK needs far fewer
round-trips for the same walk to begin with, so it's far less exposed
to that same loss in the first place."""
META = {
    "id": "snmp_brute",
    "name": "SNMP Community Brute",
    "category": "Network Exploitation",
    "test_type": "va",
    "control": "Default-credential / community-string hygiene",
    "fix": "SD-WAN",
    "mitre": ['T1110.001'],
    "cwe": ['CWE-1392'],
    "tactic": 'Credential Access',
    "requires": ["snmpbulkwalk"],
    "ports": [("udp", 161)],
    "port_customizable": True,
    "success_regex": r"STRING|INTEGER|OID",
    "blocked_regex": r"Timeout|No Response|timed out",
}


def run(target, ctx):
    # -r1 (1 retry) so a filtered/closed UDP 161 resolves in ~6s instead of the
    # default ~30s (5 retries x timeout) — snmpbulkwalk is otherwise the long pole.
    port = ctx.get_port("snmp_brute", 161)   # overridable per-attack (GUI/env)
    agent = "{target}" if port == 161 else f"{{target}}:{port}"
    return ctx.run_cmd(f"snmpbulkwalk -v2c -c public -t3 -r1 {agent}", target)
