"""Family B — DNS-over-HTTPS bypass across multiple resolvers (+ attacker DoH).

doh_bypass tests one public resolver (Cloudflare). This tests the full set from
config ("doh_providers": Cloudflare/Google/Quad9/NextDNS by default) PLUS your own
attacker-controlled DoH endpoint ("attacker_doh") — the harder case, because a
custom DoH domain is indistinguishable from ordinary HTTPS to an uncategorised
site. Any provider that returns an answer over 443 = internal DNS filtering /
logging / sinkholing is bypassed = a finding.

NON-DESTRUCTIVE: benign A lookups. MITRE T1071.004 / T1572.
"""
import subprocess
from modules import _util as U

META = {
    "id": "doh_multi",
    "name": "DNS-over-HTTPS Bypass (multi-resolver + attacker DoH)",
    "category": "Network Exploitation",
    "test_type": "attack_sim",
    "family": "B",
    "direction": "a2b",
    "added": True,
    "control": "Forced internal resolver / DoH blocking (443)",
    "fix": "SD-WAN",
    "mitre": ["T1071.004", "T1572"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": ["curl"],
    "ports": [],
    "success_regex": r"^RESOLVED ",
    "blocked_regex": r"all DoH resolvers blocked",
}

_QNAME = "example.com"


def _doh(url, ctx):
    """curl one DoH endpoint; (ok, detail). Handles both the JSON API (…/resolve,
    cloudflare dns-json) shape by asking for application/dns-json."""
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}name={_QNAME}&type=A"
    # retry a one-off transient blip so the egress verdict doesn't flap run-to-run
    argv = ["curl", "-s", "-S", "-m", "10", "--retry", "2", "--retry-connrefused",
            "--retry-delay", "1", "-H", "accept: application/dns-json"]
    if ctx.source_ip:
        argv += ["--interface", ctx.source_ip]
    argv.append(full)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=40)  # room for --retry 2
        body = (p.stdout or "") + (p.stderr or "")
        if '"Answer"' in body or '"data"' in body or '"Status"' in body:
            return True, "answer returned"
        low = body.lower()
        if "timed out" in low or "could not resolve" in low or "connection refused" in low \
                or "ssl certificate" in low or "curl:" in low:
            return False, body.strip().splitlines()[-1][:80] if body.strip() else "no response"
        return False, (body.strip().splitlines()[-1][:80] if body.strip() else "no answer")
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except FileNotFoundError:
        return False, "curl not found"
    except Exception as e:
        return False, str(e)


def run(target, ctx):
    providers = list(ctx.cfg("doh_providers", []) or [])
    att = ctx.cfg("attacker_doh")
    if att:
        providers.append(att)
    if not providers:
        # No resolvers configured and no attacker DoH → nothing to probe. Returning
        # the "all blocked" line here would score a false BLOCKED (control win) for a
        # test that never ran.
        return U.skip("no doh_providers / attacker_doh configured (config.json) — "
                      "nothing to probe for the multi-resolver DoH test.")
    out = ["# multi-resolver DoH bypass test (Family B)"]
    resolved = []
    for url in providers:
        ok, detail = _doh(url, ctx)
        label = "attacker-DoH" if url == att else url
        if ok:
            resolved.append(label)
            out.append(f"RESOLVED {label} — {detail}")
        else:
            out.append(f"blocked  {label} — {detail}")
    out.append("")
    if resolved:
        note = " (incl. your attacker-controlled DoH — indistinguishable from HTTPS)" \
               if att in [p for p in providers] and "attacker-DoH" in resolved else ""
        out.append(f"[FINDING] DoH bypass works via: {', '.join(resolved)}{note}. "
                   "Internal DNS filtering/logging is bypassed over 443.")
    else:
        out.append("all DoH resolvers blocked — forced internal resolver / DoH blocking holding")
    return "\n".join(out)
