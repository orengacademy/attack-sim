# CLAUDE.md

Guidance for Claude Code (and humans) working in this repo. Read this first; the
user-facing **[README.md](README.md)** has the full operator manual, and
**[deploy/DEPLOY.md](deploy/DEPLOY.md)** / **[deploy/cloud/README.md](deploy/cloud/README.md)**
cover the lab targets.

## What this is

A **Control Validation Harness / Breach-&-Attack-Simulation (BAS)** tool for a
purple-team engagement (internal codename **MyGovNet**, ticket **ORG2026-70**).
It runs a fixed battery of real attacks against a lab target through an SD-WAN /
segmentation boundary and records, per attack, whether the control **blocked**,
**detected**, or **let it through**. A Tkinter GUI (`gui.py`) and a headless CLI
(`cli.py`) drive the **same engine** (`core.py`). Each attack is one
auto-discovered file in `modules/`. Every run writes full raw evidence +
JSON/CSV/TXT summaries + a MITRE ATT&CK Navigator layer to `evidence/run_<ts>/`.

**Scope framing (USS):** the engagement's Attack-Simulation scope is *boundary
egress / segmentation control validation* across 7 ATT&CK families **A–G** (see
`additional/mygovnet-attack-sim-plan.html`). Modules are tagged with a
`test_type` so the USS set stays separate from the pentest/VA/DoS workstreams.

## Run / test / check

```bash
python3 gui.py                       # GUI (needs $DISPLAY); defaults to the ORIGINAL set ticked
python3 cli.py --list                # list all discovered modules + their scope tags
python3 cli.py --confirm-roe         # bare run: DEFAULTS to target 127.0.0.1 + the ORIGINAL 11-module set
python3 cli.py --target <IP> --attack-sim --confirm-roe   # headless USS run (--confirm-roe is MANDATORY)
python3 cli.py --target <IP> --all --confirm-roe          # run ALL 48 modules (default is the original set)
python3 cli.py --target <IP> --full-report --confirm-roe  # also echo report.txt (default: clean table only)
python3 cli.py --target <IP> --site-id ORG2026-70 --debug --confirm-roe  # tag the run + verbose tool trace/timing
python3 fleet.py --dry-run --attack-sim                   # N-target matrix preview (no traffic); then --confirm-roe
python3 preflight.py                 # tools + Python-package check (no network); --json for CI; --target <IP[,IP...]> adds recon (multi-target)
python3 bootstrap.py                 # Kali/Debian apt install (degrades on non-apt); --with-active adds tunnel/exec tools
python3 -m pip install -r requirements.txt   # the in-process AD modules' Python libs (impacket/ldap3/ldapdomaindump/dnspython)
python3 -m unittest discover -s tests   # test suite (pure stdlib, localhost-only, offline)
```
Per-target options (source IP, `--cloud` SMB/RPC ports, `--domain/--dc-user/
--dc-pass` creds, **and separate `--ssh-user/--ssh-pass`**) are **remembered per
target** in a `0600 .target_memory.json` (CLI flags + GUI fields) — a Linux SSH
lab and a Windows DC keep different creds. SSH creds are deliberately distinct
from the DC creds (a dual-role target is both an SSH host and a DC front, and one
identity can't serve both; `ssh_brute` falls back to the DC creds only when the
SSH ones are unset). CLI output: both GUI and CLI run **preflight + recon first**
(service/port health), then the CLI prints clean numbered live results and a
modern end-of-run **table** (verdict strip + per-row verdict/module/category/
detail); the full ATT&CK/CWE/CVE `report.txt` is always written to evidence and
echoed to the console only with `--full-report`.
Keep the lab alive with `deploy/refresh-lab.sh --install-cron` (restarts dead
services/containers/VM every 5 min). Engine is pure-stdlib and runs on any OS;
tool-dependent modules are `os_supported`-gated / PREREQ-MISSING elsewhere.

- **`--confirm-roe` (CLI) / the ROE checkbox (GUI) is required** — the tool runs
  real attacks. Never add a path that bypasses it.
- Tests are **pure-stdlib, cross-platform, localhost-only, and must stay offline.**
  They cover the classifier, preflight, reachability, credential/redaction,
  allowlist, the socket modules, and robustness (crashing/hanging/bad-regex
  modules degrade gracefully). Keep new tests to that standard.
- `wmiexec.py` / some AD modules need `impacket` installed; without it the loader
  prints `[loader] skipped ...` and moves on — that is expected, not a failure.

## Architecture

| File | Role |
|------|------|
| `core.py` | **The engine.** `Context` (handed to each module), `Evidence` (the `run_<ts>/` tree + `finalize()` which writes summaries + a self-contained **report.html** + the ATT&CK Navigator layer), `classify()` + `Runner` (orchestrates N iterations, preflight gating, recon, verdicts, DETECTED scoring), and all the preflight/reachability/privilege/platform helpers. **Attack logic does NOT live here.** |
| `loader.py` | Auto-discovers `modules/*.py` that expose `META` + `run(target, ctx)`. Files starting with `_` (helpers, `_vendor/`) are skipped. No registration anywhere. |
| `gui.py` | Tkinter dark-theme front-end. Worker thread + queue so the UI never freezes. Live log + live raw-output panel (click a status row to jump), Preflight+recon button, Egress-probe button, per-row custom port, mode/workers selectors, per-target Domain/User/Pass **and separate SSH user/pass** fields (the SSH pair feeds `ssh_brute`, falling back to the DC pair when blank). |
| `cli.py` | Headless equivalent; every GUI option as a flag (`--original` (DEFAULT) / `--all` / `--added` / `--attack-sim` / `--family` / `--cloud` / `--source` / `--domain` / `--dc-user` / `--dc-pass` / `--ssh-user` / `--ssh-pass` / `--full-report` / …). Defaults: `--target 127.0.0.1`, original 11-module set. Suppresses the engine's interleaved per-module log on the console and re-renders clean numbered live lines + a modern end-of-run **table** (verdict strip + verdict/module/category/detail columns). `report.txt` goes to evidence always; `--full-report` echoes it too. |
| `fleet.py` | **N-target front end.** Runs the same engine over a fleet of vuln servers defined in `fleet.json` (git-ignored; `fleet.json.example` committed) — a zone-to-zone matrix (`targets`×`sources`×`runs`), both directions, per-target `cloud_ports`, per-source egress binding. Reuses `cli._select` + `core.Runner` per job; evidence under `evidence/fleet_<ts>/<source>__<target>/`, plus `fleet_summary.json`. |
| `preflight.py` | Standalone cross-platform tool/privilege/recon checker; CI gate (exit 0 only if all discovered modules are ready). |
| `bootstrap.py` | One-shot apt installer for Kali/Debian. |
| `modules/` | **One file per attack**, auto-discovered. See "Adding a module". |
| `modules/_*.py` | Shared helpers (not modules): `_util.py`, `_portpatch.py` (NAT SMB/RPC port patching), `_dcompatch.py`, `_clockskew.py`, `_impacket.py` (resolve an impacket tool across flavours — `impacket-X`/`X.py`/the example script — so AD modules don't need the Kali CLI). `_vendor/` holds vendored PoCs (PetitPotam, noPac). |
| `additional/` | `mygovnet_egress_probe.py` (standalone egress/segmentation probe, launched from GUI too), `reverse_runner.py` (drop-in B→A runner for a host you can't install on), `sangfor_ingest.py` (**vendor-agnostic** SD-WAN/firewall log correlator — pure stdlib, `.xlsx` or `.csv`, column names matched by synonym in `_CANON` so Sangfor / Forcepoint / others all parse). Takes a `--log` (session/traffic: per-port Allow/Deny) and/or `--ips` (threat log: maps the signature "Attack Type" → modules; takes precedence), `--target`, `--model "<appliance>"`; `--write` merges a `detections.json` so attacks the appliance SAW score DETECTED (seen-but-allowed) and signature hits carry a prevention=yes/no note. Engine itself is appliance-agnostic — testing *through* any SD-WAN (Sangfor/Forcepoint/…) needs no code change; only this correlator is format-specific.), the plan HTML. |
| `deploy/` | Lab-target provisioning (⚠ lab only), **2-in-1**: `setup_all.sh`/`setup_target.sh` turn *any mainstream Linux* into the vuln target (distro-agnostic — detects apt/dnf/yum/pacman/zypper/apk + systemd/OpenRC) and `setup_target.sh` auto-writes a git-ignored `credentials.env` so `ssh_brute` works out of the box. Plus `docker-compose.yml` (Apache 41773 / Log4Shell / OpenLDAP). **Two targets:** the Linux host (Target #1, configured in place) and the Windows AD DC (Target #2, a VM) — `setup_all.sh --with-windows` boots the DC too (Vagrant+VirtualBox, needs HW virt). `windows/` = a single `vagrant up` that runs both provisioning passes (`provision.ps1` reads `USS_PROVISION_NO_REBOOT` so Vagrant drives the reboot; cloud self-reboots via a startup task). `windows/qemu/` = a QEMU/libvirt path (`create-dc.sh`) for KVM hosts; `cloud/` = Terraform AWS/Azure/GCP (ingress locked to `tester_cidrs`). `refresh-lab.sh --install-cron` keeps the lab alive (restarts dead services/containers/VM every 5 min). ⚠ `nopac`/`samaccountname_spoof` need an **unpatched** DC; `wmiexec`/`nopac`/`dcsync` need the **`impacket` library**. |

## The module contract

Each `modules/<name>.py` exposes a `META` dict and `run(target, ctx) -> str`
(returns the **full raw output**, which becomes evidence). Key `META` keys:

- **Identity/report:** `id`, `name`, `category`, `control`, `fix`.
- **Classification regexes:** `success_regex` (a hit), `blocked_regex` (a block),
  optional `detected_regex` (module self-reports a blue-team detection).
- **BAS mappings:** `mitre` (list), `tactic`, `cwe` (list), `cve` — these drive
  the coverage matrix + Navigator layer. Add them so a new module shows up there.
- **Preflight/recon:** `requires` (binaries), `needs_root`, `requires_files`,
  `os_supported`, `serial` (must run alone), `ports` (for recon +
  custom-port override), `port_customizable`, `added` (keeps it out of the
  "Original set" selector).
  - **DoS modules (`icmp_flood`, `syn_flood`)** test a **boundary rate-limit**, not
    target saturation (a single host can't saturate a remote target → the old
    "target packet loss" model always dead-ended at NO-RESULT). They measure a
    **differential**: normal-rate vs high-rate traffic. High-rate delivered → the
    boundary doesn't rate-limit it → SUCCESS (finding); normal-rate works but
    high-rate is dropped (loss delta ≥ 30 pts) or RTT-shaped (≥ 6× AND ≥ 150 ms
    absolute — the floor stops LAN queueing being a false BLOCKED) → BLOCKED
    (policed). `syn_flood` also flags DoS impact if real connects fail during the
    flood. Decisive in both a bare lab (SUCCESS) and behind a policing SD-WAN (BLOCKED).
  - **`serial: True`** covers two classes: (1) DoS/brute (`icmp_flood`,
    `syn_flood`, `ssh_brute`, `stateful_evasion`) that skew each other's
    rate/latency, and (2) the in-process AD modules (`dcsync`, `psexec`,
    `wmiexec`, `nopac`, `samaccountname_spoof`) which swap **process-global**
    state (`_portpatch`'s `socket.connect` monkeypatch + `redirect_stdout`) and
    would, under `--workers > 1`, pollute each other's output (→ NO-RESULT) or
    un-patch mid-connection. `nopac`+`samaccountname_spoof` additionally collide
    (both rename a machine account to the DC's name). Serial ⇒ deterministic.
  - **`run_last: True`** (`ssh_brute`, `icmp_flood`, `syn_flood`): a module whose
    SIDE EFFECT persists and would contaminate OTHERS — brute-force trips an IP
    **blacklist**, DoS floods trip **anti-DoS rate-limiting** of the source. The
    engine sorts these to the end of the serial batch so a blacklist/rate-limit
    they trigger can't turn later attacks into **false BLOCKEDs**. (A persisted
    blacklist can still bleed into a *subsequent iteration*; one iteration is clean.)
- **USS scope:** `test_type` (`attack_sim` | `pentest` | `va` | `dos`), `family`
  (`A`–`G`), `direction` (`a2b` default | `b2a` | `both`), `active` (advertises
  active-establishment capability).

`ctx` gives: `ctx.run_cmd(template, target)` (shlex-split `subprocess`, **no shell
pipes** — output auto-redacted + saved), `ctx.creds` (`domain`/`dc_user`/`dc_pass`),
`ctx.cfg(key)` (operator config, never hardcode infra), `ctx.get_port(name, default)`,
`ctx.bind_source(sock)` (bind to `--source` egress IP), and `ctx.allow_active`
(the active-establishment gate — see below). Modules must be **crash-safe**: the
Runner wraps each in an exception boundary + wall-clock watchdog, but return clear
`[ERROR]`/`[WARN]`/`[SKIP]` lines (the classifier surfaces them in the verdict).

## Verdict model (single-target mode)

Scored from the attacker side; **the raw `.log` files are authoritative** — every
classifier bug so far was caught by reading them, not by trusting the verdict.

- **SUCCESS** — passed and not detected → the finding (red).
- **DETECTED** — passed but the SOC alerted (orange). Populated from an
  operator-supplied `detections.json` / `HARNESS_DETECTIONS` / a module's
  `detected_regex`. Prevention failed, detection worked.
- **BLOCKED** — filtered/dropped in transit (timeout / filtered port) → control
  likely worked (green).
- **NO-SERVICE** — port closed/refused (RST): service absent, **not** a control
  block (blue). Recon distinguishes closed-vs-filtered so a closed port isn't
  miscredited to the control. The refused→NO-SERVICE gate is suppressed when the
  attack ports are actually **open** — an incidental "Connection refused" (e.g. a
  stray ancillary lookup) must not rob a reachable, hardened target of the
  BLOCKED verdict its own `blocked_regex` earned (this is why patched noPac now
  scores BLOCKED, not NO-SERVICE).
- **AUTH-FAILED** — credential error (fix `HARNESS_DC_PASS`), not a control result.
- **NO-RESULT** — no clear marker; surfaces the `[ERROR]/[WARN]/[SKIP]` hint.
- **PREREQ-MISSING** — skipped by preflight (missing tool/file/privilege/OS).

White-box vs black-box is a **posture recorded per result**, not different
execution: run allow-all (white-box) to confirm an attack works, then black-box
to see what the boundary stops. PASSED white-box + BLOCKED black-box = control works.

## Operator files — ALL git-ignored, NEVER commit, no live infra in source

Copy the `*.example` and fill in; env vars override the files:

| File | Env | Purpose |
|------|-----|---------|
| `credentials.env` | `HARNESS_DOMAIN`/`HARNESS_DC_USER`/`HARNESS_DC_PASS` | Lab AD creds. Password redacted (`***`) from all evidence. Never defaults to a real secret. |
| `config.json` | `HARNESS_CFG_<KEY>` | Destinations the USS modules aim at (your VPS/domain/DoH/canary/pivot). Unset → the module `[SKIP]`s. **This is how "no live infra hardcoded" is enforced — keep it that way.** |
| `allowlist.txt` | `HARNESS_ALLOWLIST` | Opt-in hard target allowlist. Unconfigured → any validated target allowed. |
| `detections.json` | `HARNESS_DETECTIONS` | Blue-team confirmations that drive the DETECTED verdict. |
| `.target_memory.json` | (CLI flags / GUI fields) | **0600.** Per-target memory: `source`, `cloud`+`smb_port`/`rpc_port`/`ssh_port`, per-target creds `domain`/`dc_user`/`dc_pass`, **separate `ssh_user`/`ssh_pass`**, and `site_id`. Lets a Linux target and a Windows DC carry different logins; recalled when flags/fields are omitted (the GUI also resumes the last-used target + its saved values on launch). |
| `fleet.json` | — | N-target fleet for `fleet.py` (`targets`/`sources`/`runs`). |
| `requirements.txt` | — | Committed; Python libs for the in-process AD modules (`pip install -r`). Engine itself needs none. |

Also: `HARNESS_PORT_<ID>` (custom port), `HARNESS_SOURCE_IP` (egress bind),
`HARNESS_SITE_ID` (engagement/site tag), `HARNESS_DEBUG` (verbose tool trace).

**`--debug` / Debug checkbox** (`ctx.debug`): injects a verbose flag into an
allowlisted set of tools (curl `-v`, ldapsearch `-v`, hydra `-d`, impacket
`-debug`), streams each module's full raw output live on the console, and shows a
per-module **TIME** column + `duration_s` in every `result.json`. **Site ID**
(`--site-id` / GUI field / `HARNESS_SITE_ID`) is recorded in `summary.json` meta,
`run.log`, and the CLI header. Both opt-in; normal runs stay clean.

## Active establishment (`--active`)

Off by default: live modules (tunnels, SOCKS pivots, DNS tunnels, exfil, beacon)
run **non-destructive indicator checks only**. `--active` (CLI) + matching
`config.json` infra lets them actually establish, always with mandatory tear-down,
only inside the authorised window. Gate reads `ctx.allow_active`. When adding/
editing a live module, keep the indicator-only default and the tear-down.

## Conventions & guardrails when editing

- **Don't hardcode attacker infra or targets** — read `ctx.cfg(...)`; unset → `[SKIP]`.
- **No secrets to disk or git** — password comes from env/file and is redacted.
- **Preserve crash-proofing** — exception boundary + per-call timeouts; one bad
  module must never abort a run, and `finalize()` must always write summaries.
- **Keep the ROE gate.** Keep recon advisory (a filtered port may *be* the control).
- **Tag new modules fully** (`test_type`/`family`/`direction`/`mitre`/`cwe`) so
  they appear in scope filters and the coverage report automatically.
- **Evidence folder is `DD-MM-HH-MM`** (`Evidence.ts`); same-minute collisions are
  de-duped. Don't reintroduce a seconds-free collision.
- Match surrounding code style; this repo favours dense explanatory comments on
  the *why*.

## Git / workflow

- Default branch `main`; work on a feature branch, open PRs (the recent history is
  all squashed/merged PRs tagged `ORG2026-70`).
- Commit messages end with the Co-Authored-By trailer; PR descriptions end with the
  Generated-with-Claude-Code line (per the session's attribution reminder).
