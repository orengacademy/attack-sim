# Control Validation Harness (Kali) — modular

Tkinter GUI that runs a fixed set of attacks against a lab target and records
whether each one worked. Each attack is its **own file** in `modules/` and
the GUI **auto-discovers** them — drop a new module in and it appears on
next launch. Each cycle runs N iterations (default 3), and the **full raw
output of every simulation** is saved to `evidence/run_<timestamp>/` with
JSON / TXT / CSV summaries.

No config file — the only input is the **Target IP** typed into the GUI and
ticking **Rules-of-engagement confirmed**. Everything else static (lab AD
credentials, per-command timeout) is preconfigured in `core.py`
(`DEFAULT_CREDENTIALS` / `DEFAULT_TIMEOUT`) — edit there if the lab
domain/creds change.

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
│   └── _vendor/PetitPotam.py   # vendored PoC (github.com/topotam/PetitPotam)
└── evidence/               # created at run time
```

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
    # --- preflight (all optional) ---
    "requires": ["some-tool"],               # external binaries this module needs
    "needs_root": False,                     # True if it needs root/admin (raw sockets, priv ports)
    "requires_files": [],                    # data files that must exist (e.g. a vendored PoC)
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
- **AUTH-FAILED** — credential error (wrong `dc_user`/`dc_pass` in `core.py`), not a control result.
- **BLOCKED** — attack failed/unreachable → control likely working (or service not present).
- **NO-RESULT** — no success and no clear block marker → review the raw log
  (may be a silent block, a patched/hardened target, or a monitor-only mode).

Automated verdicts are best-effort (regex against the raw output). **The raw
`.log` files are the authoritative evidence** — every classifier bug found
in this project so far was caught by reading them, not by trusting the verdict.

## Safety

- **No allowlist** — the harness will run against whatever IP you type in the
  GUI. Rules-of-engagement confirmation is the only gate; double-check the
  target before clicking RUN.
- PetitPotam only coerces + captures (via Responder) — it does not relay or
  crack the captured hash.
- ICMP Flood and PetitPotam are live, disruptive tests — only run inside an
  authorised maintenance window.
