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
(ldapsearch), `hping3`, `responder`, `python3-tk`.

### Privileges (you do NOT have to run the whole harness as root)

The root-needing modules (`icmp_flood`, `syn_flood`, `petitpotam`) **self-elevate
the specific tool** via `sudo -n` when you're not root. `-n` is non-interactive —
**sudo never prompts for a password**; it runs if a `NOPASSWD` rule covers that
tool, otherwise the module reports a clear privilege error (it never hangs on a
hidden prompt). Pick whichever fits your setup:

- **Run as a normal user with per-tool `NOPASSWD`** (recommended — this is why
  `sudo python3 gui.py` used to prompt: `python3` wasn't in your NOPASSWD). Add,
  via `sudo visudo`:
  ```
  youruser ALL=(root) NOPASSWD: /usr/bin/hping3, /usr/sbin/responder
  ```
  then just `python3 gui.py` — the tools elevate themselves, no prompt.
- **Sudoer but NO NOPASSWD (you have sudo, but it asks for a password)** — cache
  your sudo credentials once and `sudo -n` works for ~15 min:
  - in the GUI click **Unlock sudo** (prompts for the password, not stored), or
  - run `sudo -v` in the *same terminal* before `python3 gui.py`.
  Run root-needing modules within the ~15-min window; re-unlock to extend.
- **Or grant `hping3` the capability once** (no sudo needed for the floods):
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)
  ```
- **Or run the whole harness as root:** `sudo python3 gui.py` (needs your
  password / NOPASSWD for `python3` itself).

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

## Black-box vs white-box mode

Pick a **Mode** in the GUI (or `Runner.run(..., mode="whitebox")`):

- **Black-box** (default) — traffic goes through the SD-WAN as configured; shows
  what the control blocks.
- **White-box** — you set the SD-WAN to *allow-all* first, then run this to
  confirm each attack actually works unimpeded (a baseline).

Both run **everything**; the mode is recorded per result (`mode` column in
`summary.csv`, `meta.mode` in `summary.json`, and in `report.txt`) and announced
in the log. Compare the two runs: **PASSED in white-box but BLOCKED in black-box
= the control is working**; PASSED in both = a real gap; BLOCKED in white-box too
= the attack/service itself didn't work (not a control result).

Result colours follow purple-team convention: **red = attack PASSED (got through
— finding)**, **green = BLOCKED (control worked)**, amber = review, grey = skipped.

## Performance / concurrency

- **Recon is parallel** — all target ports are probed concurrently (a thread
  pool), so a target with several filtered ports no longer serialises one
  timeout after another.
- **Concurrent module execution** — set **Workers > 1** in the GUI (or
  `Runner.concurrency = N` headless) to run parallel-safe modules at once.
  Modules flagged `serial` in their `META` (the DoS floods and the SSH
  rate-limit test) always run **alone** so they can't skew each other's
  latency/rate-limit results. Default is `1` (fully sequential, unchanged).
  Parallelism helps most when many modules are reachable and network latency
  dominates; a single slow module is still the long pole.

### Custom ports (per-attack)

Modules with `"port_customizable": True` (Apache, Log4Shell, FTP, SSH, SNMP,
LDAP, SYN-flood) read their target port from the context, so you can point them
at a non-standard port three ways:
- **GUI** — edit the port box on the attack's row;
- **env** — `HARNESS_PORT_<ID>=8983` (e.g. `HARNESS_PORT_LOG4SHELL=8983`);
- **headless** — `Runner(...).ctx.port_overrides = {"log4shell": 8983}`.

### Egress probe (integrated)

`additional/mygovnet_egress_probe.py` is a self-contained, **non-destructive**
egress/segmentation probe (TCP port sweep, TLS carrier, L4-vs-L7 on 443, direct
external DNS, DoH, ICMP), with source-IP binding (`-s`), `--dry-run`, `--json`,
and MITRE ids. Launch it from the GUI with the **Egress probe** button (runs
against the current target, streams into the live log), or standalone:
```bash
python3 additional/mygovnet_egress_probe.py -d <dest> -s <source-ip> --tests ports,dns,doh
```

## Run

```bash
cd harness
python3 gui.py       # run as your user; root-needing tools self-elevate via sudo -n
```

The GUI's **Preflight + recon** button checks tools/privileges AND (when a target
is entered) probes the target's ports/services, colour-coded.

### Headless / SSH (no display) — use the CLI

On a server (no `$DISPLAY`) the GUI can't open; use `cli.py` — same engine, all
options as flags:

```bash
python3 cli.py --list
python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe        # self-test on the box
python3 cli.py --target 10.0.0.5 --only ssh_brute,ftp_anonymous --workers 4 --confirm-roe
python3 cli.py --target 10.0.0.5 --original --iterations 3 --confirm-roe
python3 cli.py --target 10.0.0.5 --port log4shell=8983,ssh_brute=2222 --confirm-roe
```

`--confirm-roe` is required (the CLI's rules-of-engagement gate). Selection:
`--only <ids>` / `--original` / `--added` (default: all). Output is colour-coded
(red = passed, green = blocked, blue = no-service) and the ATT&CK/CWE/CVE
coverage report + evidence path print at the end.

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
    # --- BAS mappings (recommended: appear in the ATT&CK/CWE coverage report) ---
    "mitre": ["T1190"],                      # MITRE ATT&CK technique id(s)
    "tactic": "Initial Access",              # ATT&CK tactic
    "cwe": ["CWE-22"],                       # CWE id(s), if applicable
    # --- preflight + recon (all optional) ---
    "requires": ["some-tool"],               # external binaries this module needs
    "needs_root": False,                     # True if it needs root/admin (raw sockets, priv ports)
    "serial": False,                         # True = must run alone (DoS/brute)
    "os_supported": None,                    # e.g. ["Linux"]; None = any OS
    "requires_files": [],                    # data files that must exist (e.g. a vendored PoC)
    "ports": [("tcp", 443)],                 # port(s) it targets; recon + custom-port override
    "added": False,                          # True keeps it out of the "Original set" selector
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
- **BLOCKED** — traffic was **filtered / dropped in transit** (port filtered, or a
  timeout) → the control (SD-WAN/segmentation) likely stopped it.
- **NO-SERVICE** — the target port was **closed / refused** (RST): the service
  isn't running or isn't accessible, so the attack couldn't apply. This is **NOT**
  an SD-WAN block — it's distinguished from BLOCKED precisely so a closed port
  isn't miscredited to the control. (Recon decides closed-vs-filtered.)
- **NO-RESULT** — no success and no clear block marker → review the raw log
  (may be a silent block, a patched/hardened target, or a monitor-only mode).
- **PREREQ-MISSING** — the module was skipped before running because a required
  tool/file/privilege was absent or it isn't supported on this OS (see preflight).

Automated verdicts are best-effort (regex against the raw output). **The raw
`.log` files are the authoritative evidence** — every classifier bug found
in this project so far was caught by reading them, not by trusting the verdict.

## BAS mappings (MITRE ATT&CK / CWE)

Every module declares its **MITRE ATT&CK** technique(s) (`mitre`), **tactic**
(`tactic`), and **CWE**(s) (`cwe`) in `META`, so the harness runs as a proper
**Breach & Attack Simulation**: results are standards-aligned, not just pass/fail.

- Mappings are carried into every evidence record (`summary.json` / `summary.csv`).
- `report.txt` ends with a **MITRE ATT&CK COVERAGE** matrix — per technique:
  which attacks map to it and whether any **PASSED** (`GAP`), all **BLOCKED**
  (`OK`), or mixed/other (`REVIEW`) — plus a **CWE COVERAGE** list.
- `summary.json`'s `meta.attack_coverage` / `meta.cwe_coverage` / `meta.cve_coverage`
  hold the same, machine-readable.
- **`attack_navigator_layer.json`** is written each run — import it directly at
  [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to
  visualise coverage (red = GAP/passed, green = OK/blocked, amber = REVIEW).
- CVE-based modules also carry a `cve` (e.g. CVE-2021-41773, CVE-2021-44228).

Coverage spans Initial Access (T1190), Credential Access (T1110/T1003.006/
T1558.003/T1558.004/T1187), Discovery (T1046/T1087.002), Lateral Movement
(T1021.002), C2 (T1572/T1571), Exfiltration (T1048.003), and Impact (T1498.001).
A new module is added to the matrix automatically once it declares `mitre`.

## Tests

```bash
python3 -m unittest discover -s tests    # or: python3 -m pytest tests
```

Pure-stdlib, cross-platform, localhost-only — covers the classifier, preflight,
reachability, credential loading, target validation/allowlist, redaction, the
socket modules, and **robustness**: a crashing module, a bad regex, an
unparseable command template, a failing UI callback, and an unwritable evidence
dir all degrade gracefully instead of aborting a run.

**Crash-proofing guarantee:** every module runs inside an exception boundary AND
a wall-clock **watchdog** (per-command timeout + 60s, overridable via
`Runner.module_hard_timeout`), so one faulty module is recorded as `NO-RESULT`
(traceback in the raw log) and a *hanging* module is abandoned — the run always
continues. Every external call carries its own timeout (`subprocess` timeouts,
socket `settimeout`), and `finalize()` always writes the summary/report even if
the run is interrupted. This is best-effort robustness, not a proof of zero
defects.

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
