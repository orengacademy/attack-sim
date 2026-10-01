"""Family A — Living-off-trusted-sites (LOTS) C2 reachability.

Many C2/staging frameworks ride legitimate, high-reputation SaaS on 443 (GitHub,
Google, Microsoft Graph/Teams, Slack, Discord/Telegram, Pastebin, Dropbox) — there
is no "malicious" domain to block. This module TLS-connects to those SaaS API/CDN
endpoints and reports which are reachable. A reachable endpoint = the boundary
permits egress to consumer/uncontrolled SaaS with no CASB / tenant restriction =
the precondition for LOTS C2 = a finding. All blocked = SaaS egress controlled.

NON-DESTRUCTIVE: only a TLS handshake — nothing is staged, uploaded or beaconed.
Add engagement-specific hosts via config key "lots_saas" (list of host or
label=host). MITRE T1102 (Web Service) / T1071.001.
"""
from modules import _util as U

SAAS = [
    ("github-api", "api.github.com"),
    ("github-raw", "raw.githubusercontent.com"),
    ("google-apis", "www.googleapis.com"),
    ("ms-graph", "graph.microsoft.com"),
    ("slack", "slack.com"),
    ("discord", "discord.com"),
    ("telegram", "api.telegram.org"),
    ("pastebin", "pastebin.com"),
    ("dropbox", "content.dropboxapi.com"),
]

META = {
    "id": "lots_saas_c2",
    "name": "LOTS SaaS C2 Egress (GitHub/Graph/Slack/…)",
    "category": "Egress / C2",
    "test_type": "attack_sim",
    "family": "A",
    "direction": "a2b",
    "added": True,
    "control": "CASB / consumer-SaaS egress control (443)",
    "fix": "SD-WAN",
    "mitre": ["T1102", "T1071.001"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [],          # egress test — not a target-port probe
    "success_regex": r"^REACHABLE ",
    "blocked_regex": r"all LOTS SaaS endpoints blocked",
}


def _extra(ctx):
    out = []
    for item in (ctx.cfg("lots_saas", []) or []):
        if "=" in str(item):
            label, host = str(item).split("=", 1)
        else:
            label, host = str(item), str(item)
        out.append((label.strip(), host.strip()))
    return out


def run(target, ctx):
    out = ["# LOTS SaaS C2 egress test (Family A — CASB / SaaS egress control)",
           "# target is unused: this tests THIS host's egress path through the SD-WAN."]
    reachable = []
    for label, host in SAAS + _extra(ctx):
        ok, detail = U.tls_reachable(host, 443, ctx)
        if ok:
            reachable.append(label)
            out.append(f"REACHABLE {label} ({host}) — {detail}")
        else:
            out.append(f"blocked   {label} ({host}) — {detail}")
    out.append("")
    if reachable:
        out.append(f"[FINDING] SaaS egress permitted to: {', '.join(reachable)} — "
                   "C2/staging over trusted SaaS could establish; CASB / consumer-SaaS "
                   "egress control is not enforced.")
    else:
        out.append("all LOTS SaaS endpoints blocked — SaaS egress control holding")
    return "\n".join(out)
