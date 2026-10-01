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
python3 gui.py                       # GUI (needs $DISPLAY); root-needing tools self-elevate via sudo -n
python3 cli.py --list                # list all discovered modules + their scope tags
python3 cli.py --target <IP> --attack-sim --confirm-roe   # headless USS run (--confirm-roe is MANDATORY)
python3 preflight.py                 # tools/privs check (no network); --json for CI; --target <IP> adds active recon
python3 bootstrap.py                 # install core tooling (Kali/Debian apt); --with-active adds tunnel/exec tools
python3 -m unittest discover -s tests   # test suite (pure stdlib, localhost-only, offline)
```

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
| `core.py` | **The engine.** `Context` (handed to each module), `Evidence` (the `run_<ts>/` tree + `finalize()` which writes summaries + the ATT&CK Navigator layer), `classify()` + `Runner` (orchestrates N iterations, preflight gating, recon, verdicts, DETECTED scoring), and all the preflight/reachability/privilege/platform helpers. **Attack logic does NOT live here.** |
| `loader.py` | Auto-discovers `modules/*.py` that expose `META` + `run(target, ctx)`. Files starting with `_` (helpers, `_vendor/`) are skipped. No registration anywhere. |
| `gui.py` | Tkinter dark-theme front-end. Worker thread + queue so the UI never freezes. Live log + live raw-output panel (click a status row to jump), Preflight+recon button, Egress-probe button, per-row custom port, mode/workers selectors. |
| `cli.py` | Headless equivalent; every GUI option as a flag. Colour-coded output (red=passed, green=blocked, blue=no-service). Prints `report.txt` tail (coverage) at the end. |
| `preflight.py` | Standalone cross-platform tool/privilege/recon checker; CI gate (exit 0 only if all discovered modules are ready). |
| `bootstrap.py` | One-shot apt installer for Kali/Debian. |
| `modules/` | **One file per attack**, auto-discovered. See "Adding a module". |
| `modules/_*.py` | Shared helpers (not modules): `_util.py`, `_portpatch.py` (NAT port patching), `_dcompatch.py`, `_clockskew.py`. `_vendor/` holds vendored PoCs (PetitPotam, noPac). |
| `additional/` | `mygovnet_egress_probe.py` (standalone egress/segmentation probe, launched from GUI too), `reverse_runner.py` (drop-in B→A runner for a host you can't install on), the plan HTML. |
| `deploy/` | Lab-target provisioning (⚠ lab only), **2-in-1**: `setup_all.sh`/`setup_target.sh` turn *any mainstream Linux* into the vuln target (distro-agnostic — detects apt/dnf/yum/pacman/zypper/apk + systemd/OpenRC) and `setup_target.sh` auto-writes a git-ignored `credentials.env` so `ssh_brute` works out of the box. Plus `docker-compose.yml` (Apache 41773 / Log4Shell / OpenLDAP), `windows/` (Vagrant AD DC), `cloud/` (Terraform AWS/Azure/GCP). ⚠ `nopac`/`samaccountname_spoof` need an **unpatched** DC; `wmiexec`/`nopac`/`dcsync` need the **`impacket` Python module** (bootstrap ensures it). |

## The module contract

Each `modules/<name>.py` exposes a `META` dict and `run(target, ctx) -> str`
(returns the **full raw output**, which becomes evidence). Key `META` keys:

- **Identity/report:** `id`, `name`, `category`, `control`, `fix`.
- **Classification regexes:** `success_regex` (a hit), `blocked_regex` (a block),
  optional `detected_regex` (module self-reports a blue-team detection).
- **BAS mappings:** `mitre` (list), `tactic`, `cwe` (list), `cve` — these drive
  the coverage matrix + Navigator layer. Add them so a new module shows up there.
- **Preflight/recon:** `requires` (binaries), `needs_root`, `requires_files`,
  `os_supported`, `serial` (must run alone — DoS/brute), `ports` (for recon +
  custom-port override), `port_customizable`, `added` (keeps it out of the
  "Original set" selector).
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
  miscredited to the control.
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

Also: `HARNESS_PORT_<ID>` (custom port), `HARNESS_SOURCE_IP` (egress bind).

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
