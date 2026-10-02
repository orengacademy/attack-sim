"""SSH brute-force via hydra — tests the boundary's brute-force protection by
actually generating a burst of rapid failed logins (not a single check).

Why a burst: a brute-force IPS signature only fires on VOLUME. The lab's Sangfor
"SSH Server Brute Force Exploit" (Vuln 11080017) uses Fast protection = 30
attempts in 1 minute. A single login attempt (the old behaviour) can never trip
that — so it neither tests the control nor shows up in the IPS log. This module
now fires ATTEMPTS (default 35, > the 30/min threshold) wrong passwords as fast
as hydra will go, with the one known-valid credential appended LAST, so:

  - all the wrong attempts happen first -> the brute-force signature fires
    (detection), and the boundary's rate-limit/blacklist (if any) kicks in;
  - then the valid credential is tried. If it still succeeds, brute-force
    protection did NOT stop the attack (SUCCESS — a finding; the IPS likely only
    DETECTED it). If the valid credential is now refused/dropped, the control
    rate-limited/blocked the burst (BLOCKED — protection works).

Tripping the signature may get the tester IP blacklisted by the appliance
(that's the control working) — which can also affect later modules; ssh_brute is
`serial` and runs near the end to limit that. Authorised window only.

ATTEMPTS is overridable: HARNESS_SSH_BRUTE_ATTEMPTS, or --port ssh_brute=<port>
for a non-22 port.
"""
import os
import shlex
import tempfile

META = {
    "id": "ssh_brute",
    "name": "SSH Brute Force",
    "category": "Network Exploitation",
    "test_type": "va",
    "control": "Brute-force protection / rate-limit (SSH)",
    "fix": "SD-WAN",
    "mitre": ['T1110.001'],
    "cwe": ['CWE-307'],
    "tactic": 'Credential Access',
    "requires": ["hydra"],
    "serial": True,     # rate-limit/brute test: run alone so it isn't skewed
    "run_last": True,   # the burst trips a brute-force signature that BLACKLISTS the
                        # tester IP — run after everything else so that blacklist
                        # can't turn later modules into false BLOCKEDs
    "ports": [("tcp", 22)],
    "port_customizable": True,
    # hydra's valid-pair line "login: X   password: Y" -> the brute got through.
    "success_regex": r"login:.*password:",
    # BRUTE-BLOCKED = the known-valid cred was NOT accepted after the burst (the
    # control rate-limited/blocked it); plus network-level blocks.
    "blocked_regex": r"^BRUTE-BLOCKED|timed out|Connection refused|No route|Network is unreachable",
}

DEFAULT_ATTEMPTS = 35   # > the Sangfor Fast threshold (30 / 1 min) so the signature fires


def run(target, ctx):
    port = ctx.get_port("ssh_brute", 22)   # overridable per-attack (GUI/env)
    # Cloud target: SSH is NAT'd to an alternate port (default 2222, like
    # 445->4445 / 135->1135). hydra is a subprocess so the _portpatch
    # socket.connect redirect doesn't reach it — read the alt port from the map
    # directly. An explicit --port ssh_brute=<n> override still wins.
    if port == 22:
        try:
            from modules import _portpatch
            alt = (_portpatch.CUSTOM_PORT_TARGETS.get(target) or {}).get(22)
            if alt:
                port = int(alt)
        except Exception:
            pass
    # SSH creds are SEPARATE from the DC creds (HARNESS_SSH_USER/PASS or the
    # per-target --ssh-user/--ssh-pass): a dual-role target is both an SSH host
    # and a DC front, and one identity can't serve both. Fall back to the DC
    # creds only when the SSH ones are unset.
    user = (ctx.creds.get("ssh_user") or ctx.creds.get("dc_user") or "").strip() or "root"
    pw = ctx.creds.get("ssh_pass") or ctx.creds.get("dc_pass") or ""
    if not pw.strip():
        return (f"# ssh_brute vs {target}\n\n[SKIP] no SSH password configured "
                "(set HARNESS_SSH_PASS / --ssh-pass, or HARNESS_DC_PASS / "
                "credentials.env) — nothing to test. deploy/setup_target.sh "
                "writes a credentials.env for the lab user.")

    try:
        attempts = max(5, int(os.environ.get("HARNESS_SSH_BRUTE_ATTEMPTS", DEFAULT_ATTEMPTS)))
    except ValueError:
        attempts = DEFAULT_ATTEMPTS

    # Build a password list: (attempts-1) wrong guesses + the real one LAST, so the
    # volume of FAILED logins happens first (tripping the N/min brute signature)
    # before the valid credential is tried. Written to a 0600 temp file (not the
    # argv) so the cleartext password never lands in the command line / evidence.
    ctx.creds["ssh_user"] = user
    ctx.creds["ssh_pass"] = pw                    # so _redact() scrubs it from output
    fd, wordlist = tempfile.mkstemp(prefix="ssh_brute_", suffix=".lst")
    try:
        with os.fdopen(fd, "w") as f:
            for i in range(attempts - 1):
                f.write(f"Wrong-Guess-{i:03d}-aX9!\n")
            f.write(pw + "\n")                    # the known-valid credential, last
        os.chmod(wordlist, 0o600)

        out = [f"# ssh_brute vs {target}:{port} — {attempts} rapid attempts "
               f"({attempts - 1} wrong + 1 valid last) to exercise brute-force protection"]
        # -t 4 (SSH-friendly parallelism) still clears 35 attempts well inside a
        # minute; -f stops once the valid pair is accepted. -I = ignore any restore
        # file so repeated runs don't resume a prior session.
        raw = ctx.run_cmd(
            f"hydra -s {port} -I -t 4 -f -l {{ssh_user}} -P {shlex.quote(wordlist)} "
            f"ssh://{{target}}", target)
        out.append(raw)

        import re
        if re.search(r"login:.*password:", raw):
            out.append("\n[+] a valid credential was accepted DESPITE the burst — "
                       "brute-force protection did NOT stop it (finding; the IPS likely "
                       "only DETECTED it). Correlate with the appliance's brute-force log.")
        elif re.search(r"\b0 valid passwords? found\b", raw):
            # the valid cred WAS in the list but wasn't accepted -> the control
            # rate-limited / blocked / blacklisted the burst before it got there.
            out.append("\nBRUTE-BLOCKED: the known-valid credential was NOT accepted after "
                       f"{attempts} rapid attempts — the boundary rate-limited/blocked the "
                       "brute-force burst (protection works; the signature should have fired).")
        # otherwise: hydra errored mid-run (refused/timeout) -> blocked_regex/NO-RESULT
        return "\n".join(out)
    finally:
        try:
            os.remove(wordlist)
        except OSError:
            pass
