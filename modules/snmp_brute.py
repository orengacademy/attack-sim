"""SNMP community string brute force. Walks wordlists/snmp_communities.txt
(falls back to just 'public' if that file is missing), stopping at the
first community that gets real MIB data back — 'public' is deliberately
LAST in that wordlist: it's the one the old single-check version of this
module always tried, so landing on anything else FIRST is the more
interesting finding (a non-default string someone picked is still a
guessable one), and 'public' working is the unsurprising baseline case.

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
to that same loss in the first place. -t3 -r1 also means a full ~15-word
wordlist costs at most ~1-2 min before landing on (or exhausting) the
list — most of that only paid once, on the way to whichever community
actually works."""
import os
import re

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
    # match a real net-snmp VALUE line ("... = STRING: ...") rather than a bare
    # type word — "OID" alone also appears inside error text ("...at this OID").
    "success_regex": r"= (STRING|INTEGER|Counter32|Gauge32|Timeticks|Hex-STRING|IpAddress|OID|OPAQUE):",
    "blocked_regex": r"Timeout|No Response|timed out",
}

WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists", "snmp_communities.txt")


def _load_communities():
    try:
        with open(WORDLIST) as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return words or ["public"]
    except FileNotFoundError:
        return ["public"]  # wordlist missing -> fall back to the old single-check behaviour


def run(target, ctx):
    # -r1 (1 retry) so a filtered/closed UDP 161 resolves in ~6s instead of the
    # default ~30s (5 retries x timeout) — snmpbulkwalk is otherwise the long pole.
    port = ctx.get_port("snmp_brute", 161)   # overridable per-attack (GUI/env)
    agent = "{target}" if port == 161 else f"{{target}}:{port}"

    communities = _load_communities()
    out = [f"# SNMP community brute vs {target} — {len(communities)} communities "
           f"(snmpbulkwalk, 'public' tried last)"]

    for community in communities:
        out.append(f"\n--- trying community '{community}' ---")
        raw = ctx.run_cmd(f"snmpbulkwalk -v2c -c {community} -t3 -r1 {agent}", target)
        out.append(raw)
        if re.search(META["success_regex"], raw):
            out.append(f"\n[+] SUCCESS: community string '{community}' is valid "
                       f"({'default/well-known' if community == 'public' else 'non-default, still guessable'})")
            return "\n".join(out)

    out.append(f"\n[-] All {len(communities)} communities tried — none returned valid MIB data")
    return "\n".join(out)
