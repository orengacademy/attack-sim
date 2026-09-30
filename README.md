# Control Validation Harness (Kali) — modular

Tkinter GUI that runs a fixed set of attacks against a lab target and records
whether each one worked. Each attack is its **own file** in `modules/` and
the GUI **auto-discovers** them — drop a new module in and it appears on
next launch. Each cycle runs N iterations (default 3), and the **full raw
output of every simulation** is saved to `evidence/run_<timestamp>/` with
JSON / TXT / CSV summaries.

The main input is the **Target IP** typed into the GUI plus ticking
**Rules-of-engagement confirmed**. Credentials are **not** stored in source —
the password comes from the environment or a git-ignored `credentials.env`
(see [Credentials & safety](#credentials--safety)). The per-command timeout
(`DEFAULT_TIMEOUT`) lives in `core.py`.

## Credentials & safety

- **Credentials** (no secrets in git): set `HARNESS_DOMAIN`, `HARNESS_DC_USER`,
  `HARNESS_DC_PASS` as env vars, or copy `credentials.env.example` →
  `credentials.env` (git-ignored) and fill it in. Env vars win over the file;
  the password defaults to empty if neither is set. The password is **redacted**
  (`***`) from all evidence logs so it never lands on disk.
- **Target allowlist** (opt-in): the target is validated (must be a real IP or
  hostname), and if you configure an allowlist — `HARNESS_ALLOWLIST` (comma/space
  separated) and/or a git-ignored `allowlist.txt` (see `allowlist.txt.example`) —
  the harness refuses any target not on it. With no allowlist configured,
  behaviour is unchanged (any validated target is allowed).

## Layout

```
harness/
├── gui.py                 # RUN THIS
├── core.py                # engine: subprocess ctx, evidence, classifier, runner, preflight
├── preflight.py           # standalone tool/privilege check (cross-platform, CI-friendly)
├── loader.py               # auto-discovers modules/*.py
├── modules/                # ONE FILE PER ATTACK (auto-discovered)
│   ├── apache_41773.py     # Apache Path Traversal (CVE-2021-41773)
│   ├── log4shell.py        # Log4Shell (CVE-2021-44228) — reachability check
│   ├── snmp_brute.py       # SNMP Community Brute (public)
│   ├── icmp_flood.py       # ICMP Flood (DoS) — needs hping3 raw-socket cap
│   ├── ssh_brute.py        # SSH credential check (hydra)
│   ├── ftp_anonymous.py    # FTP Anonymous Login
│   ├── doh_bypass.py       # DNS-over-HTTPS filtering bypass (Cloudflare)
│   ├── dcsync.py           # DCSync (impacket-secretsdump)
│   ├── kerberoast.py       # Kerberoast (impacket-GetUserSPNs)
│   ├── psexec.py           # PsExec lateral movement
│   ├── ldap_null_bind.py   # LDAP anonymous/null bind
│   ├── petitpotam.py       # PetitPotam NTLM coercion + Responder capture — needs root
│   ├── kerberos_asrep.py   # Kerberos AS-REP roast (no creds; impacket-GetNPUsers)
│   ├── segmentation_sweep.py # sensitive mgmt/DB/lateral port exposure A->B (pure sockets)
│   ├── appid_port_mismatch.py # App-ID / protocol-on-wrong-port bypass (pure sockets)
│   ├── covert_channel.py   # ICMP/DNS tunnelling & DNS-egress test (ping/dig, Linux)
│   ├── syn_flood.py        # SYN Flood (DoS) — needs hping3 raw-socket cap, Linux
│   └── _vendor/PetitPotam.py   # vendored PoC (github.com/topotam/PetitPotam)
├── tests/                  # stdlib unittest suite (python3 -m unittest discover -s tests)
└── evidence/               # created at run time
```

These last five target what an **SD-WAN itself** enforces (segmentation, App-ID,
covert-channel/egress, DoS, and Kerberos exposure to the DC) — i.e. the A→B path
through the SD-WAN — rather than app-layer/WAF controls that sit at the agency.

## Install (Kali)

```bash
python3 bootstrap.py
```

Installs: `curl`, `snmp` (snmpwalk), `hydra`, `impacket-scripts`, `ldap-utils`
(ldapsearch), `hping3`, `responder`, `python3-tk`. Two of the modules need
elevated privileges at run time:

- **ICMP Flood** (`hping3` needs a raw socket) — grant it once:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)
  ```
- **PetitPotam** (Responder binds privileged ports + does raw poisoning) —
  run the harness itself with `sudo` when you want this attack included:
  ```bash
  sudo python3 gui.py
  ```

## Preflight (check tools & privileges before running)

Every module declares what it needs in its `META` — the external binaries
(`requires`), whether it needs root/admin (`needs_root`), and any data files
(`requires_files`). Check them all **before** a run:

```bash
python3 preflight.py            # human-readable report
python3 preflight.py --json     # machine-readable (CI)
python3 preflight.py --versions # also probe tool versions (safe tools only)
```

It's cross-platform (Linux / macOS / Windows): it detects the OS, distro, and
package manager (apt/dnf/yum/pacman/zypper/apk, brew, winget/choco/scoop, or
pip where there's no distro package) and prints an install command for whatever
is missing. Exit code is `0` only if every discovered module is ready, so it
drops into CI as a gate.

The harness runs this **automatically** at the start of every run: unmet
modules are logged and **skipped** with a `PREREQ-MISSING` verdict instead of
executing into a "tool not found" log. To force them to run anyway (they'll
self-report), call `Runner.run(..., skip_unready=False)`. The GUI has a
**Preflight** button that shows the same report for the ticked attacks.

### Reachability recon (preliminary target test)

Each module also declares the port(s) it hits (`ports` in `META`). Before the
exploits run, the harness does a **pure-socket TCP-connect recon** of those
ports (no `nmap`, no root — works the same on Linux/macOS/Windows) so results
can tell *"service absent / port filtered"* apart from *"the exploit itself was
blocked"*, and it **suggests** which attacks are worth running (their service is
reachable). Standalone:

```bash
python3 preflight.py --target <IP>   # recon the target's ports first
```

Recon is **advisory** — it does not skip anything, because a filtered port may
*be* the control under test. It is also **active**: `--target` (and the recon
phase of a run) contacts the target, so it needs the same authorisation as the
exploits. The plain `preflight.py` (no `--target`) contacts nothing.

## Run

```bash
cd harness
python3 gui.py       # or: sudo python3 gui.py (needed for PetitPotam)
```

In the GUI: type the **Target IP**, set iterations (default 3), tick the
attacks you want, tick **Rules-of-engagement confirmed**, click **RUN**.

## Adding a new attack

Create `modules/<name>.py` with a `META` dict and a `run(target, ctx)` function:

```python
META = {
    "id": "my_attack",
    "name": "My New Attack",
    "category": "Network Exploitation",     # groups it in the GUI
    "control": "Brute-force protection",
    "fix": "SD-WAN",
    "success_regex": r"...",                 # marks a successful/detected hit
    "blocked_regex": r"timed out|refused",   # marks a block
    # --- preflight + recon (all optional) ---
    "requires": ["some-tool"],               # external binaries this module needs
    "needs_root": False,                     # True if it needs root/admin (raw sockets, priv ports)
    "requires_files": [],                    # data files that must exist (e.g. a vendored PoC)
    "ports": [("tcp", 443)],                 # port(s) it targets; used for reachability recon
}

def run(target, ctx):
    return ctx.run_cmd("some-tool {domain}/{dc_user}:{dc_pass}@{target}", target)
    # or arbitrary custom Python (subprocess etc.) — see icmp_flood.py / petitpotam.py
```

`ctx.run_cmd(...)` runs a single command (no shell pipes/redirects — it's
`shlex.split` + `subprocess.run`, not a shell) and returns the FULL raw
output, which the harness saves as evidence. `ctx.creds` exposes
`domain`/`dc_user`/`dc_pass` for modules that need custom orchestration
instead of a template string. No registration needed — new files are
auto-discovered (any file starting with `_`, like `_vendor/`, is skipped).

## Evidence

```
evidence/run_<ts>/
├── run.log                              # full engine log (same stream as the GUI's Live log panel)
├── summary.json / summary.csv / report.txt
├── iteration_1/<attack_id>/target.log   # FULL raw output
│                          /result.json
├── iteration_2/ ...
└── iteration_3/ ...
```

## Verdicts (single-target mode)

- **SUCCESS** — attack succeeded against the target → finding.
- **AUTH-FAILED** — credential error (wrong `HARNESS_DC_USER`/`HARNESS_DC_PASS`), not a control result.
- **BLOCKED** — attack failed/unreachable → control likely working (or service not present).
  If recon showed the target port filtered/closed, the verdict says so (segmentation vs service absent).
- **NO-RESULT** — no success and no clear block marker → review the raw log
  (may be a silent block, a patched/hardened target, or a monitor-only mode).
- **PREREQ-MISSING** — the module was skipped before running because a required
  tool/file/privilege was absent or it isn't supported on this OS (see preflight).

Automated verdicts are best-effort (regex against the raw output). **The raw
`.log` files are the authoritative evidence** — every classifier bug found
in this project so far was caught by reading them, not by trusting the verdict.

## Tests

```bash
python3 -m unittest discover -s tests    # or: python3 -m pytest tests
```

Pure-stdlib, cross-platform, localhost-only — covers the classifier, preflight,
reachability, credential loading, target validation/allowlist, redaction, the
socket modules, and **robustness**: a crashing module, a bad regex, an
unparseable command template, a failing UI callback, and an unwritable evidence
dir all degrade gracefully instead of aborting a run.

**Crash-proofing guarantee:** every module runs inside an exception boundary, so
one faulty module is recorded as `NO-RESULT` (with its traceback in the raw log)
and the run continues; `finalize()` always writes the summary/report even if the
run is interrupted. This is best-effort robustness, not a proof of zero defects.

## Safety

- **Target allowlist** — validated targets only; configure `HARNESS_ALLOWLIST` /
  `allowlist.txt` to hard-restrict which hosts the harness will touch. Rules-of-
  engagement confirmation is still required in the GUI — double-check the target
  before clicking RUN.
- **No secrets on disk** — the password is read from the environment / git-ignored
  `credentials.env` and redacted from all evidence logs.
- **Recon is active** — the reachability precheck contacts the target, so it needs
  the same authorisation as the exploits.
- PetitPotam only coerces + captures (via Responder) — it does not relay or
  crack the captured hash.
- ICMP Flood and PetitPotam are live, disruptive tests — only run inside an
  authorised maintenance window.
