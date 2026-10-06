"""SSH brute-force — tests the boundary's brute-force protection by generating a
rapid burst of SSH **connection attempts** (not a single check), then verifying
whether a valid credential still gets through.

WHY A CONNECTION BURST (and not just "more hydra passwords"):
The lab's Sangfor "SSH Server Brute Force Exploit" (Vuln 11080017, see
devices/sdwan/sangfor/bforce.jpeg) fires on VOLUME: Fast protection = 30 attempts
in 1 minute. SSH is encrypted, so the appliance CANNOT see individual auth
failures inside a session — it counts SSH *connections/sessions* per source per
minute. That distinction is the whole bug this module used to have:

  hydra multiplexes many password guesses onto a FEW reused TCP connections
  (one connection carries up to the server's MaxAuthTries guesses before hydra
  reconnects). So `hydra -t 4 -f` with 35 passwords finishes in ~2.5s having
  opened only a handful of TCP sessions. The harness "tried 35 passwords" but the
  appliance only ever SAW ~4-9 SSH sessions — far below 30/min — so the
  brute-force signature never fired and nothing showed up in the IPS log.
  (Confirmed against a real engagement: the Sangfor session log recorded just 9
  TCP/22 sessions to the target across a whole day, max 3 in any minute, and the
  threat log had zero SSH-brute events — while the signature was enabled.)

So step 1 now fires a burst of N INDEPENDENT TCP connections to the SSH port
(default 40 > the 30/min threshold), each completing the SSH identification-string
exchange so the appliance's DPI classifies every one as a real SSH session. N
distinct sessions in a few seconds is exactly what a connection-rate brute
signature counts — so it now actually trips (and, per the signature's own
recommendation, the appliance may blacklist the tester source: that IS the control
working).

Step 2 then runs hydra for the real credential test — wrong guesses first, the one
known-valid credential LAST — so:
  - if the valid credential is still accepted after the burst -> brute-force
    protection did NOT stop the attack (SUCCESS — a finding; the IPS likely only
    DETECTED it, correlate the appliance brute-force/IPS log);
  - if it is now refused/dropped -> the control rate-limited/blacklisted the burst
    (BRUTE-BLOCKED — protection works).

Tripping the signature may get the tester IP blacklisted by the appliance (that's
the control working) and can affect later modules; ssh_brute is `serial` +
`run_last` so it runs near the very end to limit that. Authorised window only.

Overridable:
  HARNESS_SSH_BRUTE_CONNS     connection-burst size (default 40; keep it > the
                              appliance's attempts/min threshold — 30 on the lab).
  HARNESS_SSH_BRUTE_ATTEMPTS  hydra password tries in the credential test (default 35).
  --port ssh_brute=<port> / HARNESS_PORT_SSH_BRUTE   non-22 SSH port.
"""
import os
import shlex
import socket
import tempfile
import threading
import time

META = {
    "id": "ssh_brute",
    "name": "SSH Brute Force",
    "category": "Network Exploitation",
    # DEAD LAST (order 100, after icmp_flood/DoS at 99). The brute burst trips an
    # SSH-brute signature that BLACKLISTS the whole tester source, and that ban
    # lasts LONGER than the DoS anti-flood lockout (and longer than the wait-unblock
    # window) — so if anything ran after ssh_brute it would be stuck INCONCLUSIVE
    # waiting for a ban that won't clear in time. Running it absolutely last means
    # its long blacklist contaminates nothing; the shorter DoS bans (icmp/syn) that
    # run just before it DO clear inside the wait window.
    "order": 100,
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

DEFAULT_ATTEMPTS = 35   # hydra password tries in the credential test
# Connection-burst size. MUST exceed the appliance's brute-force threshold
# (Sangfor Fast = 30 attempts / 1 min on the lab) with margin, because the
# signature counts SSH *connections* per minute, not passwords.
DEFAULT_CONNS = 40
BURST_WORKERS = 12          # bounded concurrency for the burst (SSH-friendly)
BURST_CONNECT_TIMEOUT = 4.0  # per-connection connect/handshake budget (seconds)
# Our SSH client identification string. Sending a valid "SSH-2.0-..." banner is
# what makes the appliance's app-id classify each connection as a real SSH
# session (and thus count it toward the brute-force signature).
_CLIENT_IDENT = b"SSH-2.0-MyGovNet_BAS_bruteprobe\r\n"


def _connection_burst(target, port, count, ctx):
    """Open `count` INDEPENDENT TCP connections to the SSH port as fast as we can
    (bounded concurrency), each completing the SSH identification-string exchange
    then closing. Returns a counters dict. Fully crash-safe — never raises; a
    failed connection is just tallied."""
    tally = {"ok": 0, "refused": 0, "timeout": 0, "other": 0}
    lock = threading.Lock()
    sem = threading.BoundedSemaphore(BURST_WORKERS)

    def _one():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                ctx.bind_source(s)            # egress-bind to --source when set
                s.settimeout(BURST_CONNECT_TIMEOUT)
                s.connect((target, port))
                # a real (if aborted) SSH session: read the server ident, send
                # ours, read a little, then drop. Enough for DPI to count it as SSH.
                try:
                    s.recv(256)
                    s.sendall(_CLIENT_IDENT)
                    s.recv(64)
                except OSError:
                    pass                       # handshake cut short still = a session seen
                with lock:
                    tally["ok"] += 1
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        except ConnectionRefusedError:
            with lock:
                tally["refused"] += 1
        except socket.timeout:
            with lock:
                tally["timeout"] += 1
        except OSError:
            with lock:
                tally["other"] += 1
        finally:
            sem.release()

    threads = []
    for _ in range(count):
        sem.acquire()
        t = threading.Thread(target=_one, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=BURST_CONNECT_TIMEOUT + 2)
    return tally


def run(target, ctx):
    # SSH attacks hit port 22 by DEFAULT. An operator can override it per-target
    # (GUI SSH field / --ssh-port / .target_memory.json "ssh_port") or per-attack
    # (--port ssh_brute=N / HARNESS_PORT_SSH_BRUTE); when a port IS set it wins and
    # we don't second-guess it (no service-probe fallback — "always 22 unless set").
    # hydra is a subprocess so the _portpatch socket.connect redirect can't reach
    # it; read any operator-set alt from the map here so an explicit cloud SSH port
    # (e.g. a 22->2222 NAT) still reaches hydra. Absent an override this is 22.
    port = ctx.get_port("ssh_brute", 22)
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
    try:
        conns = max(5, int(os.environ.get("HARNESS_SSH_BRUTE_CONNS", DEFAULT_CONNS)))
    except ValueError:
        conns = DEFAULT_CONNS

    ctx.creds["ssh_user"] = user
    ctx.creds["ssh_pass"] = pw                    # so _redact() scrubs it from output

    out = [f"# ssh_brute vs {target}:{port} — brute-force protection test "
           f"(step 1: {conns}-connection burst to trip the signature; "
           f"step 2: {attempts}-password credential test)"]

    # ---- step 1: connection burst (the signature trigger) --------------------
    # Fire `conns` independent SSH connections fast. A brute-force IPS signature
    # counts SSH SESSIONS/min (it can't decrypt the auth), so this — not hydra's
    # reused-connection password spray — is what actually trips it.
    t0 = time.time()
    tally = _connection_burst(target, port, conns, ctx)
    elapsed = time.time() - t0
    # Only quote a numeric per-minute rate when the burst lasted long enough for
    # one to be meaningful; on a fast path just state it landed well inside a
    # minute (the threshold is per-60s, so a sub-second burst is trivially over it).
    if elapsed >= 1.0:
        rate_s = f"effective rate ~= {tally['ok'] / elapsed * 60.0:.0f}/min"
    else:
        rate_s = "delivered in under 1s (all within the 1-min detection window)"
    out.append(
        f"\n[burst] {tally['ok']}/{conns} SSH connections established in {elapsed:.2f}s "
        f"(refused={tally['refused']} timeout={tally['timeout']} other={tally['other']}); "
        f"{rate_s}.")
    if tally["ok"] >= min(conns, 30):
        out.append("        this exceeds the Sangfor 'SSH Server Brute Force Exploit' Fast "
                    "threshold (30/min, Vuln 11080017) — the signature SHOULD now fire. "
                    "Correlate the appliance IPS/brute-force log "
                    "(additional/sangfor_ingest.py --ips ...).")
    elif tally["ok"] == 0 and (tally["refused"] or tally["timeout"]):
        # could not establish ANY SSH session — the source may already be
        # blacklisted/rate-limited, or SSH is unreachable through the boundary.
        out.append("        no SSH session could be established — the tester source may "
                    "already be blacklisted/rate-limited by the boundary, or SSH is "
                    "filtered. See the credential test below.")
    else:
        out.append(f"        NOTE: only {tally['ok']} session(s) landed — below the 30/min "
                    "threshold. If the appliance throttled the burst mid-flight that IS the "
                    "control working; otherwise raise HARNESS_SSH_BRUTE_CONNS.")

    # ---- step 2: credential test (did a valid login still get through?) ------
    # Build a password list: (attempts-1) wrong guesses + the real one LAST, so the
    # volume of FAILED logins happens first before the valid credential is tried.
    # Written to a 0600 temp file (not the argv) so the cleartext password never
    # lands in the command line / evidence.
    fd, wordlist = tempfile.mkstemp(prefix="ssh_brute_", suffix=".lst")
    try:
        with os.fdopen(fd, "w") as f:
            for i in range(attempts - 1):
                f.write(f"Wrong-Guess-{i:03d}-aX9!\n")
            f.write(pw + "\n")                    # the known-valid credential, last
        os.chmod(wordlist, 0o600)

        # -t 4 (SSH-friendly parallelism); -f stops once the valid pair is accepted;
        # -I = ignore any restore file so repeated runs don't resume a prior session.
        raw = ctx.run_cmd(
            f"hydra -s {port} -I -t 4 -f -l {{ssh_user}} -P {shlex.quote(wordlist)} "
            f"ssh://{{target}}", target)
        out.append("\n[hydra] credential test:")
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
                       f"the burst + {attempts} rapid attempts — the boundary "
                       "rate-limited/blocked/blacklisted the brute-force burst (protection "
                       "works; the signature should have fired).")
        elif tally["ok"] == 0 and (tally["refused"] or tally["timeout"]):
            # neither the burst NOR hydra could reach SSH -> treat as blocked by the
            # boundary (source blacklisted / filtered), not a silent NO-RESULT.
            out.append("\nBRUTE-BLOCKED: neither the connection burst nor the credential "
                       "test could reach SSH — the boundary appears to be dropping the "
                       "tester source (blacklist/rate-limit). Protection works.")
        # otherwise: hydra errored mid-run (refused/timeout) -> blocked_regex/NO-RESULT
        return "\n".join(out)
    finally:
        try:
            os.remove(wordlist)
        except OSError:
            pass
