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

---

# How to use — A to Z

A linear walkthrough from a fresh clone to reading results. Each step links to
the deeper section below.

## 0. What this is / what you need
- **Role:** this is the *attacker/tester* side. It runs real attacks from your
  box (**Kali** is the primary operator OS; it also runs on any Linux / Windows /
  macOS — see [Runs from any OS](#runs-from-any-os-kali--any-linux--windows--macos)).
- **You need:** Python 3 (stdlib only — no pip deps for the engine), authorisation
  (written RoE naming the targets/window), and one or more **targets** to attack.
- **The engine never needs third-party Python packages;** only the *in-process AD
  modules* need `impacket` (see `requirements.txt`).

## 1. Authorisation first (non-negotiable)
Every run requires confirming rules-of-engagement: the GUI checkbox
**"Rules-of-engagement confirmed"**, or `--confirm-roe` on the CLI/fleet. Only
point it at hosts you are **authorised, in writing**, to test, inside the agreed
window. Optionally hard-restrict targets with an [allowlist](#credentials--safety).

## 2. Install the tooling (operator box)
```bash
python3 bootstrap.py            # Kali/Debian: installs curl/snmp/hydra/impacket/ldap-utils/hping3/responder/...
python3 -m pip install -r requirements.txt   # the in-process AD modules (impacket/ldap3/ldapdomaindump/dnspython)
python3 preflight.py            # verify tools + Python packages are ready (exit 0 = all green); --json for CI
```
On a non-apt OS, `bootstrap.py` tells you to use your own package manager, and
`preflight.py` prints the exact install command for whatever's missing. **Prep is
"ready" when `preflight.py` is green — not when a run is all-SUCCESS** (see
[What "success" means](#what-success-means)).

## 3. Stand up the vulnerable target(s) — OR point at existing ones
If you're providing the lab (⚠ **lab only, isolate it**):
```bash
sudo deploy/setup_all.sh --with-tools     # any Linux -> this host becomes the Linux target (SSH/FTP/SNMP + web CVEs + 443)
sudo deploy/setup_all.sh --with-windows   # ALSO boot the Windows AD DC VM (Vagrant/VirtualBox or QEMU/libvirt)
sudo deploy/refresh-lab.sh --install-cron # keep the vuln services alive (restart any that die, every 5 min)
```
The Windows AD DC can be a Vagrant VM, a QEMU/libvirt VM, or a cloud DC
(Terraform) — see [Deploying the vulnerable target(s)](#deploying-the-vulnerable-targets).
If the targets already exist, skip this and just point the harness at their IPs.
The engagement's lab inventory (sites, IPs, postures, creds) is in **[docs/TARGETS.md](docs/TARGETS.md)** — active site: **KVDC**.

## 4. Configure (git-ignored operator files)
- **Linux target creds** → `credentials.env` (copy `credentials.env.example`);
  `setup_target.sh` writes it for the lab SSH user automatically.
- **Per-target creds** (a Linux box and a Windows DC need *different* logins) →
  set them **per target**: CLI `--domain/--dc-user/--dc-pass`, or the GUI
  Domain/User/Pass fields. Remembered per target in a `0600 .target_memory.json`.
  **SSH creds are separate** (CLI `--ssh-user/--ssh-pass`, or the GUI **SSH
  user/SSH pass** fields): a dual-role target is both an SSH host *and* a DC
  front, and one identity can't serve both — `ssh_brute` uses the SSH creds and
  falls back to the DC creds only when they're unset. (If `ssh_brute` reports
  `0 valid password found` → NO-RESULT, you gave it the DC login, not the SSH
  login; set the SSH fields.)
- **Egress infra** (for the USS A–G modules: your VPS/domain/DoH/canary/pivot) →
  `config.json` (copy `config.json.example`). Unset keys → that module `[SKIP]`s.
- **Cloud target** (SMB/RPC on NAT'd high ports) → GUI "Cloud target" tick, or CLI
  `--cloud` (`--smb-port`/`--rpc-port`; defaults 4445/1135). Remembered per target.
- **Blue-team detections** (for the DETECTED verdict) → `detections.json`.

## 5. Run it
**GUI** (defaults to the **original** module set; tick more, confirm RoE, RUN):
```bash
python3 gui.py
```
**CLI** (headless; one target per run, re-run per target):
```bash
python3 cli.py --list                                  # all modules + scope tags
python3 cli.py --confirm-roe                            # bare run: DEFAULTS to 127.0.0.1 + the original set
python3 cli.py --target 127.0.0.1 --mode whitebox --original --confirm-roe   # baseline self-test
python3 cli.py --target <ip> --all --confirm-roe              # run ALL modules (default is the original 11)
python3 cli.py --target <ip> --attack-sim --confirm-roe       # the USS boundary scope
python3 cli.py --target <DC-ip> --domain lab.local --dc-user Administrator \
  --dc-pass '<pw>' --only dcsync,kerberoast,psexec --confirm-roe   # AD vs a DC (creds remembered)
python3 cli.py --target <ip> --only ssh_brute --confirm-roe   # ssh_brute: SSH login FOLLOWS the DC/Windows Administrator by default; add --ssh-user/--ssh-pass only for a DISTINCT SSH account
```
Both the GUI and the CLI **run preflight + recon first** (tool/port/service
health) before any attack. The CLI then shows clean numbered live results and a
modern end-of-run **table** (verdict strip + verdict/module/category/detail);
the full ATT&CK/CWE/CVE `report.txt` always lands in the evidence dir and is
echoed to the console only with `--full-report`.
Typical **Kali (behind SDWAN) → cloud target**:
```bash
python3 cli.py --target <cloud-ip> --source <sdwan-foothold-ip> --cloud --attack-sim --confirm-roe
```
**Fleet** (N targets across zones, both directions — opt-in):
`python3 fleet.py --dry-run --attack-sim` then `--confirm-roe`. See
[Fleet](#fleet-n-targets-across-zones--fleetpy).

## 6. Read the results
The CLI prints a modern summary (verdict-distribution bars + a per-category table)
then the ATT&CK/CWE/CVE coverage. Everything is also saved under
`evidence/run_<ts>/` (JSON/CSV/TXT + an ATT&CK Navigator layer + full raw logs).
Verdict meanings: [Verdicts](#verdicts-single-target-mode). **The raw `.log` files
are authoritative** — automated verdicts are best-effort regex.

## 7. Tear down
```bash
sudo deploy/setup_all.sh --teardown        # removes the Linux lab + the Windows VM
sudo deploy/refresh-lab.sh --remove-cron   # stop the keep-alive
```

## What "success" means
A good run is **accurate, not all-green**. A module is SUCCESS only when (a) its
target/vuln is actually present and reachable, (b) its creds/config are set, and
(c) the attack genuinely gets through. On a single box many modules correctly
report SKIPPED (egress needs your infra), NO-SERVICE (service/DC not at that IP),
NO-RESULT (DoS can't hurt loopback; a review), or PREREQ-MISSING — those are
correct, not failures. AD modules must target a **Windows DC** (not localhost);
DoS only "succeeds" against a real saturable remote target.

---

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
- **Operator config** (git-ignored): the USS modules read the destinations they aim
  at (your VPS/domain/DoH/canary/pivot) from `config.json` (see
  `config.json.example`) or `HARNESS_CFG_*` — no live infra is hardcoded; unset →
  the module `[SKIP]`s. **Detections**: `detections.json` (see
  `detections.json.example`) / `HARNESS_DETECTIONS` feed the **DETECTED** verdict.
- **Active establishment is off by default** — live tunnels/pivots/exfil only run
  with `--active`; otherwise modules do non-destructive indicator checks.

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

**Per-module reference:** every attack — what it tests, why, what it needs, and
**how to block/prevent it** (the `control`/`fix` it validates) — is documented in
**[docs/MODULES.md](docs/MODULES.md)**, auto-generated from each module's `META` +
docstring (`python3 additional/gen_module_docs.py` to regenerate after a change).

These last five target what an **SD-WAN itself** enforces (segmentation, App-ID,
covert-channel/egress, DoS, and Kerberos exposure to the DC) — i.e. the A→B path
through the SD-WAN — rather than app-layer/WAF controls that sit at the agency.

## Deploying the vulnerable target(s)

`deploy/` provisions the lab you test against (⚠ **lab only** — isolate it). The
same repo is **2-in-1**: it both *configures a Linux box as the vulnerable target*
and *attacks it* — run `setup_all.sh` on the box, then point the harness at it (or
at `127.0.0.1` for a self-test).
- **One-shot on any mainstream Linux**: `sudo deploy/setup_all.sh` installs Docker
  if missing (apt / `get.docker.com` / native pacman·zypper·apk), runs
  `setup_target.sh`, and brings up the containers — the whole Linux target in one
  command (`--with-tools` also installs the attacker tooling; `--with-windows` also
  boots the Windows AD DC VM via Vagrant+VirtualBox when the host supports it;
  `--teardown` removes everything). If Docker can't be installed, host SSH/FTP/SNMP
  are still configured and the web containers are skipped with a warning. **Two
  targets:** the Linux host is Target #1 (configured in place); the Windows DC is
  Target #2, a separate VM (needs hardware virtualization).
- **Linux services + web CVEs** (manual): `sudo deploy/setup_target.sh` (SSH lab user,
  FTP anon, SNMP public — distro-agnostic: apt/dnf/yum/pacman/zypper/apk) then
  `cd deploy && docker compose up -d` (Apache CVE-2021-41773, Log4Shell, anonymous
  OpenLDAP). `setup_target.sh` also drops a git-ignored `credentials.env` pointing at
  the lab SSH user, so `ssh_brute` succeeds out of the box (it tests one known
  credential, `HARNESS_DC_USER`/`PASS`, not a wordlist).
- **Windows AD DC** — local bench: `cd deploy/windows && vagrant up` — one command
  installs AD DS, promotes, reboots, and seeds the accounts (Kerberoastable SPN,
  AS-REP-roastable account, weak admin). ⚠ `nopac` / `samaccountname_spoof`
  (CVE-2021-42278/42287) additionally need an **unpatched** DC — a current patched
  build makes those two correctly fail; the other AD modules still land. **KVDC /
  cloud**: use
  **[deploy/cloud/](deploy/cloud/README.md)** — Terraform (Azure module included)
  that reuses `provision.ps1` via `provision_cloud.ps1`, locked to your tester IPs.

Full steps + teardown: **[deploy/DEPLOY.md](deploy/DEPLOY.md)** · cloud/KVDC + the
reverse (B→A) direction: **[deploy/cloud/README.md](deploy/cloud/README.md)**.

## Runs from any OS (Kali · any Linux · Windows · macOS)

The **engine is pure-stdlib Python 3** (no third-party deps) and runs anywhere;
`loader` auto-discovers all modules on every OS. What differs is only which
*per-module* tools are present:

- **Kali** (the primary operator OS) — `bootstrap.py` installs everything; all
  modules run.
- **Other Linux / macOS** — install the tools with your package manager;
  `python3 preflight.py` prints the exact `apt/dnf/yum/pacman/zypper/apk/brew`
  command for whatever's missing.
- **Windows** — `curl` is built in (Win10+), `impacket` via `pip install impacket`;
  the pure-socket and in-process impacket modules (segmentation, App-ID, TLS/443,
  egress, dcsync/psexec/wmiexec/kerberoast/asrep/nopac/sAMAccountName) run. The
  Linux-only tools (`hydra`, `hping3`, `snmp`, `ldapsearch`, `responder`) aren't on
  Windows, so those modules report `PREREQ-MISSING`/skip — never a crash. The AD
  modules resolve impacket across flavours (`impacket-X` → `X.py` → the example
  script), so they need only the impacket **library**, not a Kali CLI.

**Typical run — Kali (behind the SDWAN) → a DO/cloud target:**
```bash
python3 cli.py --target <DO-public-ip> --source <your-sdwan-foothold-ip> \
  --cloud --attack-sim --confirm-roe       # --cloud: SMB->4445 / RPC->1135 (cloud NAT)
```
`--source`/`--cloud` are remembered per target (re-run `--target <ip>` alone next
time). AD modules need the DC's creds (`HARNESS_DOMAIN`/`HARNESS_DC_USER`/`HARNESS_DC_PASS`). A Linux SSH lab and a Windows DC need *different* creds, so set them **per target** — CLI `--domain/--dc-user/--dc-pass` or the GUI Domain/User/Pass fields — remembered per target in a 0600 `.target_memory.json` (they override `credentials.env`).

## Install (Kali)

```bash
python3 bootstrap.py
```

Installs: `curl`, `snmp` (snmpwalk), `hydra`, `impacket-scripts`, `ldap-utils`
(ldapsearch), `hping3`, `responder`, `python3-tk`. On a non-apt OS it prints the
right install command instead (the engine still runs — see "Runs from any OS").

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

`--confirm-roe` is required (the CLI's rules-of-engagement gate). `--target`
defaults to `127.0.0.1`. Selection: `--only <ids>` / `--original` / `--added` /
`--all` — **default is the original 11-module set** (same as the GUI). Output is
colour-coded (red = passed, green = blocked, blue = no-service): a clean numbered
live line per module, then a modern end-of-run **table** (verdict strip +
verdict/module/category/detail columns) and the evidence path. The full
ATT&CK/CWE/CVE `report.txt` is written to the evidence dir always and echoed to
the console only with `--full-report`.

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

- **SUCCESS** — attack succeeded and was **not** detected → *passed-undetected*, the finding.
- **DETECTED** — attack **passed the boundary but the blue team saw it** (detection
  works, prevention didn't). Populated from an operator-supplied `detections.json`
  (or `HARNESS_DETECTIONS`, or a module's `detected_regex`) — see
  [Detection-aware scoring](#detection-aware-scoring-blocked--detected--passed-undetected).
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

## Attack-simulation scope (USS families A–G)

The engagement's **Attack Simulation (USS)** scope — per `additional/mygovnet-attack-sim-plan.html`
— is **boundary egress/segmentation control validation** across 7 ATT&CK families.
Each module is tagged with a `test_type` so a USS run reflects that scope and isn't
mixed with other NPSA test types. Filter with `--attack-sim` or `--family`:

All **seven** families are now modularised. `test_type` keeps the USS set separate
from the other NPSA workstreams:

| test_type | in USS scope? |
|-----------|---------------|
| **attack_sim** | ✅ yes — families A–G below |
| pentest | ✗ (UPT): apache_41773, log4shell, dcsync, kerberoast, petitpotam, kerberos_asrep, nopac, samaccountname_spoof |
| va | ✗ (VA/ConfigA): snmp_brute, ssh_brute, ftp_anonymous, ldap_null_bind |
| dos | ✗ (plan says **no DoS**): icmp_flood, syn_flood |

**Family coverage (attack_sim):**

| Fam | Control validated | Modules |
|-----|-------------------|---------|
| **A** — 443 C2/tunnel | egress allow-list, TLS-inspect, App-ID | egress_tunnel_brokers, tls_carrier, l7_enforce_443, lots_saas_c2, domain_fronting, self_tunnel_vps\*, udp443_quic, ssh_over_443\* |
| **B** — DNS covert | forced internal resolver, DoH/DoT block | doh_bypass, doh_multi, dns_egress_external, dot_doq_853, dns_tunnel\* |
| **C** — TLS/proxy evasion | JA3/inspection, category, proxy, parsing | ja3_mimicry, nrd_category, proxy_bypass, http_smuggling |
| **D** — segmentation/lateral | least-privilege ACLs, micro-seg, App-ID | segmentation_sweep, appid_port_mismatch, psexec, wmiexec, reverse_egress (b2a), socks_pivot\*, eastwest_lateral\*, ipv6_acl_parity, stateful_evasion, switch_mgmt |
| **E** — exfil/DLP | DLP, volume thresholds, ICMP/DNS egress | covert_channel, dlp_canary_https, dlp_lowandslow\*, icmp_exfil\* |
| **F** — inbound/WAF (agency-owned) | WAF, DMZ egress, mgmt surface | waf_evasion, exposed_mgmt_api |
| **G** — realism overlay | NDR beacon analytics, UEBA | beacon_shaping\* |

`* = active-establishment capable` (see [Active establishment](#active-establishment)).

Run the scoped set headless:
```bash
python3 cli.py --target <IP> --attack-sim --confirm-roe            # all USS families
python3 cli.py --target <IP> --family A,B --confirm-roe            # the two client-named
python3 cli.py --target <IP> --attack-sim --direction b2a \
  --source <DC_ip> --confirm-roe                                    # reverse (server-initiated)
python3 cli.py --target <IP> --attack-sim --active --confirm-roe   # allow live establishment
```

### Detection-aware scoring (Blocked / Detected / Passed-undetected)

The purple-team deliverable is three-state, not two. The harness scores block-vs-pass
from the attacker side; to record **Detected** (passed but the SOC alerted), give it
the blue team's confirmations: copy `detections.json.example` → `detections.json`
(git-ignored) or point `HARNESS_DETECTIONS` at a file, listing the attack ids the SOC
saw. Any attack that **passes** *and* is listed scores **DETECTED** (orange in the
report / `DETECT` in the ATT&CK Navigator layer) instead of the red **SUCCESS**
(passed-undetected finding). A module can also self-report via `detected_regex`.

### Operator config (no live infra hardcoded)

The USS modules aim at destinations you control — your redirector/VPS, a domain/DoH
you own, a canary endpoint, a segmented pivot target. These are **never hardcoded**:
copy `config.json.example` → `config.json` (git-ignored) or set `HARNESS_CFG_<KEY>`
env vars. A module whose destination is unset degrades to a safe `[SKIP]` no-op.

### Active establishment

By default the live modules run **non-destructive indicator** checks (e.g. reach the
tunnel broker, don't build the tunnel). Pass **`--active`** (needs the matching
`config.json` infra) to let them actually establish — build the chisel/gost/wstunnel
or SSH-over-443 tunnel, open the SOCKS pivot, run the iodine/dnscat2 DNS tunnel,
POST the canary, or beacon — always with mandatory tear-down. Use only inside the
authorised window.

### Direction (A→B and B→A)

Every module declares a `direction`: `a2b` (SDWAN/site → DC, northbound — default),
`b2a` (DC → SDWAN/out, reverse/server-initiated), or `both`. Filter with
`--direction`, and bind egress to a foothold interface with `--source <ip>`. For the
reverse path from a DC/cloud host you can't install on, drop the self-contained
`additional/reverse_runner.py`.

## Fleet (N targets across zones) — `fleet.py`

`cli.py` runs one target; **`fleet.py` runs a whole fleet of vuln servers** across
MyGovNet zones (DO/KVDC/IPDC/PDSA/Global/PCN/SDWAN) as a **zone-to-zone matrix,
both directions**, with per-target NAT'd SMB/RPC ports and per-source egress
binding — the same engine, N times. Define the fleet in `fleet.json` (copy
`fleet.json.example`, git-ignored):

```jsonc
{
  "targets": [ {"id":"do-dc1","ip":"167.71.222.169","zone":"cloud",
                "cloud_ports":{"445":4445,"135":1135}}, ... ],   // the N vuln servers
  "sources": [ {"id":"sdwan-fh","ip":"10.20.0.5","zone":"sdwan"}, ... ], // tester footholds
  "runs":    [ {"from":"sdwan","to":["kvdc","cloud"],"direction":"a2b"},
               {"from":"kvdc","to":["sdwan"],"direction":"b2a"} ]  // the matrix
}
```

Each `run` expands to **(source foothold in `from` zone) → (every target in `to`
zones)** in the given direction. Omit `sources`/`runs` to just run every target
from the default route.

```bash
python3 fleet.py --list-targets                     # show the fleet
python3 fleet.py --dry-run --attack-sim             # preview the job matrix (no traffic)
python3 fleet.py --attack-sim --confirm-roe         # run the whole matrix (USS scope)
python3 fleet.py --to kvdc,cloud --direction a2b --confirm-roe   # scope by zone/direction
python3 fleet.py --from sdwan --only dcsync,psexec --confirm-roe
```

Evidence lands per job under `evidence/fleet_<ts>/<source>__<target>/run_<ts>/`,
with a top-level `fleet_summary.json` (per-job verdict counts) and a roll-up of
every target where an attack **PASSED** (a finding). Module selection (`--only`/
`--original`/`--attack-sim`/`--family`) and `--active`/`--workers`/`--iterations`/
`--mode` work exactly as in `cli.py`.

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
