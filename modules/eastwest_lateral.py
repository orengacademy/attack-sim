"""Family D — east-west lateral movement (WMI / WinRM / RDP / SMB).

Complements psexec: from a DC foothold, validates internal micro-segmentation and
EDR against the common remote-exec vectors — not just PsExec/SMB. It probes the
lateral ports (135 WMI/DCOM, 5985/5986 WinRM, 3389 RDP, 445 SMB) and, with valid
creds + --active, attempts a benign remote command via WMI (impacket-wmiexec) or
WinRM (evil-winrm) and reports whether it executed.

  * INDICATOR (default): which lateral ports are reachable to the target.
  * ACTIVE (--active): attempt remote exec ("whoami") with core credentials.

Reachable lateral ports between servers = segmentation/EDR gap. MITRE T1021.002 /
T1047 / T1021.006.
"""
from modules import _util as U

_LATERAL = [(135, "WMI/DCOM"), (445, "SMB"), (5985, "WinRM-HTTP"),
            (5986, "WinRM-HTTPS"), (3389, "RDP")]

META = {
    "id": "eastwest_lateral",
    "name": "East-West Lateral (WMI/WinRM/RDP/SMB)",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "direction": "both",
    "added": True,
    "active": True,
    "control": "Host firewalls between servers; EDR blocks remote-exec; tiered admin",
    "fix": "SD-WAN",
    "mitre": ["T1021.002", "T1047", "T1021.006"],
    "tactic": "Lateral Movement",
    "cwe": [],
    "requires": [],
    "ports": [("tcp", 445), ("tcp", 5985), ("tcp", 135), ("tcp", 3389)],
    "success_regex": r"^EXEC-OK|^LATERAL-OPEN",
    "blocked_regex": r"no lateral ports reachable",
}


def run(target, ctx):
    out = [f"# east-west lateral test vs {target} (Family D)"]
    reachable = []
    for port, name in _LATERAL:
        st = U.tcp_state(target, port, ctx, timeout=4)
        out.append(f"  {port}/{name} — {st}")
        if st == "open":
            reachable.append(f"{port}/{name}")
    out.append("")
    if reachable:
        out.append(f"LATERAL-OPEN — lateral port(s) reachable: {', '.join(reachable)} "
                   "(segmentation/EDR should still block the remote-exec itself).")
    else:
        out.append("no lateral ports reachable — segmentation holding for E-W remote exec")
        return "\n".join(out)

    if not ctx.allow_active:
        out.append(U.skip("--active not set — not attempting remote exec (indicator only)."))
        return "\n".join(out)

    # WMI first (135), then WinRM (5985) — whichever tool is present. run_cmd
    # substitutes {domain}/{dc_user}/{dc_pass}/{target} itself.
    if any(p.startswith("135") for p in reachable) and U.have("impacket-wmiexec"):
        out.append("[ACTIVE] impacket-wmiexec whoami …")
        res = ctx.run_cmd('impacket-wmiexec {domain}/{dc_user}:{dc_pass}@{target} '
                          '"cmd /c whoami"', target)
        out.append(res)
        low = res.lower()
        if "nt authority" in low or ("\\" in res and "error" not in low):
            out.append("EXEC-OK — remote command executed via WMI (T1047). [FINDING]")
        else:
            out.append("WMI exec did not confirm — review raw output.")
    elif any(p.startswith("5985") for p in reachable) and U.have("evil-winrm"):
        out.append("[ACTIVE] evil-winrm (non-interactive) …")
        res = ctx.run_cmd('evil-winrm -i {target} -u {dc_user} -p {dc_pass}', target)
        out.append(res)
        out.append("Review evil-winrm output for a shell (EXEC-OK if a prompt returned).")
    else:
        out.append("[SKIP] --active set but no matching exec tool for the reachable ports "
                   "(need impacket-wmiexec for 135 or evil-winrm for 5985).")
    return "\n".join(out)
