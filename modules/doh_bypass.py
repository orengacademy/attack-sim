"""DNS-over-HTTPS bypass (Family B). Does NOT attack the lab target — it tests
whether the perimeter's DNS/egress filtering can be bypassed by tunnelling DNS
over HTTPS (443) to a public DoH resolver.

The weak version of this test just resolved google.com over DoH and checked for
an answer — which only proves DoH EGRESS works, not that it bypasses a POLICY
(google.com is allowed everywhere). The strong version (this one) resolves a
domain the environment's DNS filter is supposed to BLOCK by category (a "blocked
canary") and compares three legs — exactly the chain a DoH-enabled browser does:

  1. baseline — resolve+connect the canary DIRECTLY (system resolver = the
     controlled path). On a filtering network this is sinkholed / dropped
     (HTTP 000) = the control working normally.
  2. DoH      — resolve the SAME canary over HTTPS/443 to a public resolver. An
     answer here = the DNS-layer filter never saw the query -> bypassed (finding).
  3. access   — connect to the DoH-obtained IP with the real SNI. Reaching the
     origin (any HTTP status, even a 403 bot-challenge FROM THE SITE) = the block
     was DNS-only and is FULLY bypassed; still blocked = DNS bypassed but a
     connection-layer (SNI/IP) control holds.

Canary domain: `ctx.cfg("blocked_canary_domain")` — set it to a domain YOUR policy
category-blocks (adult / gambling / malware / C2; e.g. a domain your SD-WAN
sinkholes). Unset -> a SAFE built-in category test domain (Cisco Umbrella's
`internetbadguys.com`, a benign test page, NOT real adult/malware content). A real
adult/gambling/malware site is never hardcoded in the repo — that's the operator's
per-engagement choice.

Verdict: a DoH answer (DOH-BYPASS) = SUCCESS (DNS egress/filtering bypassable, the
finding), enriched with whether the direct path was blocked (policy bypass) and
whether connecting to the DoH IP reached the origin (full vs DNS-only bypass). No
DoH answer (DOH-BLOCKED) = the control covers DoH too. The verdict is from the
TEST — posture/policy are reference only (ORG2026-70)."""
import os
import re

META = {
    "id": "doh_bypass",
    "name": "DNS-over-HTTPS Bypass",
    "category": "Network Exploitation",
    "order": 3,  # right after the Server Exploitation pair, ahead of the run_last tail
    "test_type": "attack_sim",
    "family": "B",
    "control": "DNS filtering / egress control (DNS-layer + DoH + SNI/IP)",
    "fix": "SD-WAN",
    "mitre": ['T1572'],
    "cwe": ['CWE-693'],
    "tactic": 'Command and Control',
    "requires": ["curl"],
    "trips_ips": True,   # DoH/egress signature can trip the gateway → source blacklist; run last
    "ports": [],         # egress test — no target port
    # DOH-BYPASS = DoH resolved/egressed (finding). The raw DoH JSON's "Answer"/"data"
    # is kept as a fallback signal. DOH-BLOCKED = DoH egress filtered (control held).
    "success_regex": r'DOH-BYPASS|"Answer"|"data"',
    "blocked_regex": r"DOH-BLOCKED|could not resolve|SSL certificate problem",
}

# Public DoH resolver used for the egress probe (JSON DoH API).
_RESOLVER = "cloudflare-dns.com"
# SAFE default canary: Cisco Umbrella's security-category test domain. A benign
# test page that DNS security filtering categorises/blocks — so on a filtering
# network it's sinkholed direct but resolvable over DoH. Operator overrides with a
# domain their OWN policy blocks (adult/gambling/malware) via blocked_canary_domain.
_DEFAULT_CANARY = "internetbadguys.com"


def _parse_doh_ips(text):
    """IPv4 answers from a JSON DoH response ("data":"1.2.3.4")."""
    return re.findall(r'"data"\s*:\s*"(\d{1,3}(?:\.\d{1,3}){3})"', text or "")


def _parse_code(raw, label):
    """The HTTP status a curl `-w LABEL:%{http_code}` probe printed; 000 = no
    connection (blocked / timed out)."""
    m = re.search(label + r":(\d{3})", raw or "")
    return m.group(1) if m else "000"


def _compose_verdict(canary, doh_ips, doh_responded, direct_code, access_code):
    """Pure verdict composer (so it's unit-testable offline). Returns (text, is_finding)."""
    direct_reached = direct_code != "000"
    L = []
    if doh_ips:
        L.append("DOH-BYPASS: resolved %s -> %s over DoH/443 — the DNS-layer filter never saw "
                 "the query." % (canary, ", ".join(doh_ips[:4])))
        if direct_reached:
            L.append("  [contrast] direct-by-name ALSO reached %s (HTTP %s) — no DNS block observed "
                     "on this canary from here. Run from BEHIND the boundary, or set a "
                     "blocked_canary_domain your policy actually filters, to demonstrate the bypass."
                     % (canary, direct_code))
        else:
            L.append("  [contrast] direct-by-name to %s was BLOCKED (HTTP 000, no connection) but DoH "
                     "resolved it — the DNS/category control is BYPASSED via DoH." % canary)
        if access_code != "000":
            L.append("  [access] FULL BYPASS: connected to the DoH-obtained IP with SNI %s and reached "
                     "the origin (HTTP %s — note a 4xx here can be the SITE's own bot-challenge, not the "
                     "boundary). The block was DNS-only; no SNI/IP control caught it." % (canary, access_code))
        else:
            L.append("  [access] DNS bypassed, but connecting to the DoH IP (SNI %s) was blocked — a "
                     "connection-layer (SNI/IP) control still holds; DoH defeats DNS visibility only here."
                     % canary)
        return "\n".join(L), True
    if doh_responded:
        L.append("DOH-BYPASS: DoH egress to %s is REACHABLE (a DoH response came back for %s, though no A "
                 "record) — DNS tunnelling over DoH/443 is available; point blocked_canary_domain at a "
                 "resolvable policy-blocked domain to show a resolved record." % (_RESOLVER, canary))
        return "\n".join(L), True
    L.append("DOH-BLOCKED: no DoH response for %s via %s — DoH egress to the public resolver is "
             "filtered/blocked (the control covers DoH, not just plaintext DNS)." % (canary, _RESOLVER))
    return "\n".join(L), False


def run(target, ctx):
    # target is unused — this probes the source host's own egress path, not the
    # lab target — but kept in the signature for interface consistency.
    canary = (ctx.cfg("blocked_canary_domain") or _DEFAULT_CANARY).strip()
    out = ["# DNS-over-HTTPS bypass — DNS/egress control test (blocked canary: %s)" % canary, ""]

    # ---- leg 2 first: DoH resolve the canary over HTTPS/443 --------------------
    # -S (with -s) surfaces the real error on failure instead of a blank NO-RESULT;
    # --retry rides out a one-off transient blip so the egress verdict is stable.
    doh_raw = ctx.run_cmd(
        'curl -s -S -m10 --retry 2 --retry-connrefused --retry-delay 1 '
        '-H "accept: application/dns-json" '
        '"https://%s/dns-query?name=%s&type=A"' % (_RESOLVER, canary), target)
    out += ["## DoH query (name=%s over https://%s)" % (canary, _RESOLVER), doh_raw.strip(), ""]
    doh_ips = _parse_doh_ips(doh_raw)
    doh_responded = ('"Status"' in doh_raw) or ('"Answer"' in doh_raw) or bool(doh_ips)

    # ---- leg 1: baseline — direct-by-name via the SYSTEM resolver --------------
    # The controlled path. On a filtering network this is sinkholed/dropped (000).
    # {{ }} survive ctx.run_cmd's .format(); %% -> % so curl gets %{http_code}.
    direct_raw = ctx.run_cmd(
        'curl -s -S -o %s -w "DIRECT-HTTP:%%{{http_code}}" -k --max-time 6 "https://%s/"'
        % (os.devnull, canary), target)
    out += ["## baseline: direct-by-name (system resolver, the controlled path)", direct_raw.strip(), ""]
    direct_code = _parse_code(direct_raw, "DIRECT-HTTP")

    # ---- leg 3: access-confirm — connect to a DoH IP with the real SNI ---------
    access_code = "000"
    if doh_ips:
        access_raw = ctx.run_cmd(
            'curl -s -S -o %s -w "ACCESS-HTTP:%%{{http_code}}" -k --max-time 8 '
            '--resolve %s:443:%s "https://%s/"' % (os.devnull, canary, doh_ips[0], canary), target)
        out += ["## access-confirm: connect to the DoH IP %s with SNI %s" % (doh_ips[0], canary),
                access_raw.strip(), ""]
        access_code = _parse_code(access_raw, "ACCESS-HTTP")

    verdict, _finding = _compose_verdict(canary, doh_ips, doh_responded, direct_code, access_code)
    out.append(verdict)
    return "\n".join(out)
