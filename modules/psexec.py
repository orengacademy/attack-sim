"""PsExec lateral movement via impacket-psexec. Tests SMB/RPC segmentation
+ IPS PsExec signature. Needs valid admin creds (core.DEFAULT_CREDENTIALS)
and SMB (445) reachable to the target."""
META = {
    "id": "psexec",
    "name": "PsExec Lateral Movement",
    "category": "AD Exploitation",
    "control": "Segmentation (SMB/RPC) + IPS signature",
    "fix": "SD-WAN",
    "success_regex": r"nt authority\\system|Creating service|Starting service|SVCManager|Opening SVCManager",
    "blocked_regex": r"STATUS_ACCESS_DENIED|rpc_s_access_denied|timed out|refused|unreachable|Errno",
}

def run(target, ctx):
    # Runs a single command (whoami) via a temporary service over SMB.
    return ctx.run_cmd(
        'impacket-psexec {domain}/{dc_user}:{dc_pass}@{target} "cmd /c whoami"',
        target)
