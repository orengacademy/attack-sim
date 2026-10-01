"""Family D — stateful-inspection evasion (fragmentation + source-port trust).

Probes the quality of the inter-zone firewall's stateful inspection with hping3:
  1. Fragmented SYNs to a target port — does the firewall reassemble before it
     decides, or can fragmentation slip a probe past it?
  2. Source-port 53 / 443 SYNs — does the firewall wrongly trust a "DNS/HTTPS"
     source port and allow a connection it would otherwise deny?
A response to a crafted probe that a plain SYN doesn't get = an evasion gap.

Needs hping3 + root (raw sockets); self-elevates via `sudo -n` (see README). Linux.
Low packet volume (NOT a flood). Config: eval_port (default 445). MITRE T1205.
"""
import subprocess
import shutil
from modules import _util as U
import core

META = {
    "id": "stateful_evasion",
    "name": "Stateful-inspection Evasion (frag / src-port)",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "direction": "a2b",
    "added": True,
    "control": "Reassembly-aware inspection; no trust of source port; anti-spoofing",
    "fix": "SD-WAN",
    "mitre": ["T1205"],
    "tactic": "Defense Evasion",
    "cwe": ["CWE-923"],
    "requires": ["hping3"],
    "needs_root": True,
    "os_supported": ["Linux"],
    "serial": True,             # raw-socket probes — run alone, don't skew others
    "ports": [],
    "success_regex": r"^EVASION-",
    "blocked_regex": r"no evasion gap|hping3 not",
}


def _hping(args, timeout=15):
    argv = core.sudo_prefix() + ["hping3"] + args
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return "[ERROR] hping3 not found"
    except Exception as e:
        return f"[ERROR] {e}"


def _got_reply(out):
    # hping3 prints "flags=SA" (SYN-ACK) / "flags=RA" (RST) on a reply; a purely
    # dropped probe shows "100% packet loss" and no flags line.
    return "flags=" in out and "100% packet loss" not in out


def run(target, ctx):
    if not U.have("hping3"):
        return "# stateful-evasion test\n[ERROR] hping3 not found (see preflight)"
    port = ctx.get_port("stateful_evasion", 445)
    out = [f"# stateful-inspection evasion vs {target}:{port} (Family D)"]
    findings = []

    # baseline: a plain SYN (what normal policy sees)
    base = _hping(["-S", "-c", "2", "-p", str(port), target])
    base_reply = _got_reply(base)
    out.append(f"baseline plain SYN -> port {port}: {'reply' if base_reply else 'no reply (blocked/closed)'}")

    # 1) fragmented SYN
    frag = _hping(["-S", "-f", "-c", "2", "-p", str(port), target])
    if _got_reply(frag) and not base_reply:
        findings.append("fragmented SYN passed where a plain SYN did not")
    out.append(f"fragmented SYN     -> port {port}: {'reply' if _got_reply(frag) else 'no reply'}")

    # 2) source-port 53 and 443 (does the FW trust the source port?)
    for sp in (53, 443):
        r = _hping(["-S", "-s", str(sp), "--keep", "-c", "2", "-p", str(port), target])
        if _got_reply(r) and not base_reply:
            findings.append(f"source-port {sp} SYN passed where a plain SYN did not")
        out.append(f"src-port {sp} SYN   -> port {port}: {'reply' if _got_reply(r) else 'no reply'}")

    out.append("")
    if findings:
        out.append("EVASION-GAP — " + "; ".join(findings) +
                   ". [FINDING] stateful inspection can be evaded (fragmentation / "
                   "source-port trust).")
    else:
        out.append("no evasion gap — crafted probes did not bypass the baseline result "
                   "(reassembly-aware / source-port-agnostic inspection holding)")
    return "\n".join(out)
