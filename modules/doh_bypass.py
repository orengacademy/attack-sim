"""DNS-over-HTTPS bypass check. Unlike the other modules, this doesn't
attack the lab target at all — it tests whether the perimeter appliance's
DNS filtering can be bypassed by tunnelling DNS over HTTPS (port 443) to
a public DoH resolver, matching the manual test script exactly."""
META = {
    "id": "doh_bypass",
    "name": "DNS-over-HTTPS Bypass",
    "category": "Network Exploitation",
    "control": "DNS filtering / egress control",
    "fix": "SD-WAN",
    "success_regex": r'"Answer"|"data"',
    "blocked_regex": r"timed out|Connection refused|could not resolve|SSL certificate problem|curl: \(\d+\)",
}


def run(target, ctx):
    # target is unused — this probes the Kali box's own egress path, not the
    # lab target — but kept in the signature for interface consistency.
    # -S (alongside -s) re-enables error messages that silent mode otherwise
    # suppresses too — without it, ANY failure (timeout, TLS glitch, DNS
    # resolution hiccup) comes back as a blank NO-RESULT with zero clue why.
    return ctx.run_cmd(
        'curl -s -S -m10 -H "accept: application/dns-json" '
        '"https://cloudflare-dns.com/dns-query?name=google.com&type=A"', target)
