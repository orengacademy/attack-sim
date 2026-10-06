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
python3 gui.py                       # Tkinter GUI (needs $DISPLAY); defaults to the ORIGINAL set ticked
python3 app.py                       # WEB GUI on 0.0.0.0:8080 (--host/--port/--token); same engine, live SSE
python3 cli.py --list                # list all discovered modules + their scope tags
python3 cli.py --confirm-roe         # bare run: DEFAULTS to target 127.0.0.1 + the ORIGINAL 11-module set
python3 cli.py --target <IP> --attack-sim --confirm-roe   # headless USS run (--confirm-roe is MANDATORY)
python3 cli.py --target <IP> --all --confirm-roe          # run ALL modules (default is the original set)
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

- **Rules-of-engagement confirmation is required** — the tool runs real attacks.
  Satisfied by `--confirm-roe` (per run), a DURABLE explicit opt-in via
  `--accept-roe` (writes git-ignored `.roe_accepted`) or `HARNESS_CONFIRM_ROE=1`,
  or the GUI checkbox (pre-ticked when the durable opt-in is on file). Keep it an
  explicit opt-in — never make real attacks run with NO confirmation at all
  (a durable opt-in the operator chose is fine; a silent default-on is not).
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
| `app.py` | **Web front-end** (the 3rd way to drive the engine, next to `gui.py` and `cli.py`). Pure-stdlib `ThreadingHTTPServer` on `0.0.0.0:8080` (`--host`/`--port`/`--token`); serves a modern dark **bento** dashboard that runs `core.Runner` in a background thread and streams live log/status/progress to the browser over **SSE**, with verdict meters, a module grid, a live results table, and links to each run's `evidence/` (report.html/summary.json). Keeps the ROE gate (a run is refused unless ROE is confirmed). ⚠ binding 0.0.0.0 exposes a control panel that launches real attacks — trusted lab segment / `--host 127.0.0.1` / `--token` only. |
| `gui.py` | Tkinter dark-theme front-end. Worker thread + queue so the UI never freezes. Live log + live raw-output panel (click a status row to jump), Preflight+recon button, Egress-probe button, per-row custom port, mode/workers selectors, per-target Domain/User/Pass **and separate SSH user/pass** fields (the SSH pair feeds `ssh_brute`, falling back to the DC pair when blank). |
| `cli.py` | Headless equivalent; every GUI option as a flag (`--original` (DEFAULT) / `--all` / `--added` / `--attack-sim` / `--family` / `--cloud` / `--source` / `--domain` / `--dc-user` / `--dc-pass` / `--ssh-user` / `--ssh-pass` / `--appliance` / `--full-report` / …). `--appliance <IP>` turns on **dual-path mode**: each attack runs against `--target` (the direct allow-all baseline that proves it works) AND through `--appliance` (the controlled path), and `classify()` compares them — baseline OK + appliance BLOCKED/NO-SERVICE = control works, baseline OK + appliance SUCCESS/DETECTED = finding. Defaults: `--target 127.0.0.1`, original 11-module set. Suppresses the engine's interleaved per-module log on the console and re-renders clean numbered live lines + a modern end-of-run **table** (verdict strip + verdict/module/category/detail columns). `report.txt` goes to evidence always; `--full-report` echoes it too. |
| `fleet.py` | **N-target front end.** Runs the same engine over a fleet of vuln servers defined in `fleet.json` (git-ignored; `fleet.json.example` committed) — a zone-to-zone matrix (`targets`×`sources`×`runs`), both directions, per-target `cloud_ports`, per-source egress binding. Reuses `cli._select` + `core.Runner` per job; evidence under `evidence/fleet_<ts>/<source>__<target>/`, plus `fleet_summary.json`. |
| `preflight.py` | Standalone cross-platform tool/privilege/recon checker; CI gate (exit 0 only if all discovered modules are ready). |
| `bootstrap.py` | One-shot apt installer for Kali/Debian. |
| `modules/` | **One file per attack**, auto-discovered. See "Adding a module". |
| `modules/_*.py` | Shared helpers (not modules): `_util.py`, `_portpatch.py` (NAT SMB/RPC port patching), `_dcompatch.py`, `_clockskew.py`, `_impacket.py` (resolve an impacket tool across flavours — `impacket-X`/`X.py`/the example script — so AD modules don't need the Kali CLI). `_vendor/` holds vendored PoCs (PetitPotam, noPac). |
| `additional/` | `mygovnet_egress_probe.py` (standalone egress/segmentation probe, launched from GUI too), `reverse_runner.py` (drop-in B→A runner for a host you can't install on), `sangfor_ingest.py` (**vendor-agnostic** SD-WAN/firewall log correlator — pure stdlib, `.xlsx` or `.csv`, column names matched by synonym in `_CANON` so Sangfor / Forcepoint / others all parse). Takes a `--log` (session/traffic: per-port Allow/Deny) and/or `--ips` (threat log: maps the signature "Attack Type" → modules; takes precedence), `--target`, `--model "<appliance>"`; `--write` merges a `detections.json`: signature/DENY/prevention hits score **DETECTED**, while a plain session-log ALLOW (seen-but-allowed) is recorded as a policy **reference** note on the SUCCESS verdict — NOT a detection (see `_detection_is_real()` in the verdict model). Engine itself is appliance-agnostic — testing *through* any SD-WAN (Sangfor/Forcepoint/…) needs no code change; only this correlator is format-specific.), the plan HTML. |
| `deploy/` | Lab-target provisioning (⚠ lab only), **2-in-1**: `setup_all.sh`/`setup_target.sh` turn *any mainstream Linux* into the vuln target (distro-agnostic — detects apt/dnf/yum/pacman/zypper/apk + systemd/OpenRC) and `setup_target.sh` auto-writes a git-ignored `credentials.env` so `ssh_brute` works out of the box. Plus `docker-compose.yml` (Apache 41773 / Log4Shell / OpenLDAP). **Two targets:** the Linux host (Target #1, configured in place) and the Windows AD DC (Target #2, a VM) — `setup_all.sh --with-windows` boots the DC too (Vagrant+VirtualBox, needs HW virt). `windows/` = a single `vagrant up` that runs both provisioning passes (`provision.ps1` reads `USS_PROVISION_NO_REBOOT` so Vagrant drives the reboot; cloud self-reboots via a startup task). `windows/qemu/` = a QEMU/libvirt path (`create-dc.sh`) for KVM hosts; `cloud/` = Terraform AWS/Azure/GCP (ingress locked to `tester_cidrs`). `attacker_endpoint.py` is the **attacker-infra sink** (stdlib HTTP canary + TCP/UDP sinks) you point `config.json` (`canary_url`/`attacker_vps`/`published_app_url`) at so the egress/C2/exfil modules reach a real endpoint and score SUCCESS instead of SKIP. `windows/make-nopac-vulnerable.ps1` reverts an already-patched live DC so nopac/sama work (fresh builds are already unpatched). `refresh-lab.sh --install-cron` keeps the lab alive (restarts dead services/containers/VM every 5 min). ⚠ `nopac`/`samaccountname_spoof` need an **unpatched** DC; `wmiexec`/`nopac`/`dcsync` need the **`impacket` library**. |

## The module contract

Each `modules/<name>.py` exposes a `META` dict and `run(target, ctx) -> str`
(returns the **full raw output**, which becomes evidence). Key `META` keys:

> **Per-module docs:** `docs/MODULES.md` (what each attack tests / why / needs /
> how to block) is **generated** from `META` + the module docstring by
> `additional/gen_module_docs.py` — never hand-edit it; rerun the generator after
> changing or adding a module so the reference can't drift. The `control` field is
> the remediation and `fix` is the owner, so keep both meaningful.

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
- **DETECTED** — passed AND the SOC/appliance **genuinely detected** it (orange):
  a fired IPS **signature**, an explicit **prevention** verdict, or an active
  **DENY** in the appliance log. Populated from `detections.json` /
  `HARNESS_DETECTIONS` / a module's `detected_regex`. Prevention failed, detection
  worked. ⚠ A plain session-log **ALLOW** (e.g. `ALLOW (policy=Outbound_NPSA)`) is
  **NOT** a detection — that is the appliance's own policy *reference* / telemetry
  (it SAW and PASSED the flow). `_detection_is_real()` gates this: an ALLOW/MIXED
  reference keeps the attack as **SUCCESS** (the finding) with the reference
  attached as a note, so an "allowed-and-logged" flow can't masquerade as
  "detection worked" and hide a real finding (operator instruction, ORG2026-70:
  *the policy reference is just a reference — the verdict comes from the test*).
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
- **INCONCLUSIVE** — the test couldn't reach a verdict (purple). Either the source
  was IPS-quarantined mid-run, OR a module **self-declared** `[INCONCLUSIVE]`
  because it genuinely can't decide — a UDP probe with no handshake
  (`udp443_quic`), or a coercion that fired but whose callback can't be observed
  from here (`petitpotam` against a non-routable listener). Carries the module's
  own reason instead of a mute NO-RESULT.
- **NO-RESULT** — no clear marker; surfaces the `[ERROR]/[WARN]/[SKIP]` hint.
- **PREREQ-MISSING** — skipped by preflight (missing tool/file/privilege/OS), OR a
  module self-declared `[PREREQ-MISSING]` at **runtime** when a local prerequisite
  is only discoverable then (e.g. `kerberoast` needs `faketime` once the host
  clock is skewed past Kerberos' 5-min window). Not a control result.

White-box vs black-box is a **posture recorded per result**, not different
execution: run allow-all (white-box) to confirm an attack works, then black-box
to see what the boundary stops. SUCCESS white-box + BLOCKED black-box = control works.

## Operator files — COMMITTED directly (controlled dummy lab)

> **Convention (operator decision, ORG2026-70):** this is a **controlled,
> throwaway DUMMY lab** — the operator files below are **committed as real
> `.env`/`.json` files, not `.example` templates**, so every clone is
> plug-and-play (creds + targets prefill out of the box, no copy-from-example
> step). They hold only **dummy lab creds** (`lab.local` / `Administrator`) and
> **lab target IPs**, never real-world secrets. **Do NOT re-add these to
> `.gitignore`.** Env vars (`HARNESS_*`) still override the files. If you ever
> need to point `config.json` at **real** infra, set it via `HARNESS_CFG_*` env
> vars rather than editing the tracked file.
>
> **Still NEVER committed** (real secrets / a safety gate — kept git-ignored):
> `.roe_accepted` (committing it would auto-accept ROE and bypass the
> attack-confirmation gate), Terraform `*.tfstate`/`terraform.tfvars`, and
> `deploy/nginx/certs/` (lab TLS private key). `requirements.txt` stays
> committed. Password is still redacted (`***`) from all evidence, and the
> built-in source **defaults** still never contain a secret (dc_pass default is
> `""`; the dummy password lives only in the committed `credentials.env`).

Env vars override the files:

| File | Env | Purpose |
|------|-----|---------|
| `credentials.env` | `HARNESS_DOMAIN`/`HARNESS_DC_USER`/`HARNESS_DC_PASS` | Lab AD creds. Password redacted (`***`) from all evidence. Never defaults to a real secret. |
| `config.json` | `HARNESS_CFG_<KEY>` | Destinations the USS modules aim at (your VPS/domain/DoH/canary/pivot). Unset → the module `[SKIP]`s. **This is how "no live infra hardcoded" is enforced — keep it that way.** |
| `allowlist.txt` | `HARNESS_ALLOWLIST` | Opt-in hard target allowlist. Unconfigured → any validated target allowed. |
| `detections.json` | `HARNESS_DETECTIONS` | Blue-team confirmations that drive the DETECTED verdict. |
| `port_policy.json` | `HARNESS_PORT_POLICY` | Boundary allow-list (SD-WAN/firewall). Default built-in = **Polisi Standard Security v1.3**. Checked pre-scan: a BLOCKED/NO-SERVICE on a policy-**denied** service port is labelled *expected segmentation* (not an IPS/WAF result). `port_policy.json` is committed (the Polisi v1.3 default). |
| `.target_memory.json` | (CLI flags / GUI fields) | **0600.** Per-target memory: `source`, `cloud`+`smb_port`/`rpc_port`/`ssh_port`, per-target creds `domain`/`dc_user`/`dc_pass`, **separate `ssh_user`/`ssh_pass`**, and `site_id`. Lets a Linux target and a Windows DC carry different logins; recalled when flags/fields are omitted (the GUI also resumes the last-used target + its saved values on launch). |
| `fleet.json` | — | N-target fleet for `fleet.py` (`targets`/`sources`/`runs`). |
| `requirements.txt` | — | Committed; Python libs for the in-process AD modules (`pip install -r`). Engine itself needs none. |

Also: `HARNESS_PORT_<ID>` (custom port), `HARNESS_SOURCE_IP` (egress bind),
`HARNESS_SITE_ID` (engagement/site tag), `HARNESS_DEBUG` (verbose tool trace),
`HARNESS_COOLDOWN` (pause before each brute/DoS module), `HARNESS_WAIT_UNBLOCK`
(`--wait-unblock`: how long to wait for an IPS quarantine/source-blacklist to
clear before marking the rest INCONCLUSIVE; default `max(30s, cooldown,
ban_expiry+30)`), `HARNESS_BAN_EXPIRY` (`--ban-expiry`: the appliance's known
source-blacklist auto-expiry — Sangfor "Lockout Duration", default 300s — which
sizes the wait window so a banned source is waited out, not dead-ended; 0 = old
30s window), `HARNESS_AUTO_RETRY` (`--auto-retry N`: after an iteration, re-run
attacks whose verdict was poisoned by a source-blacklist once the ban clears, so
they earn a real per-attack verdict; N rounds, default 1, 0 = off).

**`--debug` / Debug checkbox** (`ctx.debug`): injects a verbose flag into an
allowlisted set of tools (curl `-v`, ldapsearch `-v`, hydra `-d`, impacket
`-debug`), streams each module's full raw output live on the console, and shows a
per-module **TIME** column + `duration_s` in every `result.json`. **Site ID**
(`--site-id` / GUI field / `HARNESS_SITE_ID`) is recorded in `summary.json` meta,
`run.log`, and the CLI header. Both opt-in; normal runs stay clean.

## Multi-target scans & appliance (SD-WAN/IPS) testing

- **One scan, several targets:** CLI `--target B,C` (comma list) and the GUI's
  2nd-target field run the selected modules against each target with its OWN
  remembered config (on-prem DC on direct 445/135/22; cloud DC on NAT'd
  4445/1135/2222). Each target gets its own `run_<ts>__<target>` evidence dir; the
  GUI tags rows with a **Target** column. `preflight.py --target B,C` and the GUI
  Preflight button recon each target too.
- **Blacklist-contamination guard:** running from ONE source through a
  blacklisting appliance, an early attack can get the source banned so later
  attacks show a false BLOCKED. The engine picks a benign OPEN canary port at
  recon and, on any BLOCKED, re-probes it — if it went unreachable it latches,
  warns, and tags that and later BLOCKEDs `[SUSPECT: source blacklisted]`.
  `cli.py --suspect <evidence_dir>` lists them + the re-run command. Standard fix:
  whitelist the tester source on the appliance. `run_last` (ssh_brute/icmp_flood/
  syn_flood) + `--cooldown`/`HARNESS_COOLDOWN` keep the blacklisters from
  contaminating the rest. When a ban IS tripped, the engine detects it on ANY
  non-SUCCESS verdict (BLOCKED/NO-SERVICE/NO-RESULT, not just BLOCKED), waits out
  the ban (window sized by `--ban-expiry`, default 300s), and `--auto-retry`
  (default 1 round) re-tests the contaminated attacks once the source is let back
  in — so a mid-run ban yields real per-attack verdicts instead of a tail of false
  BLOCKED/INCONCLUSIVE/NO-SERVICE. Each contaminated row carries `contaminated:true`
  in evidence until a clean re-test replaces it.
- **Appliance-log correlation:** `additional/sangfor_ingest.py` (vendor-agnostic:
  Sangfor **and** Forcepoint, `.xlsx`/`.csv`, synonym column + action-value
  mapping) turns an appliance's per-port Allow/Deny (session log) and signature
  hits (IPS log, `--ips`) into a `detections.json`. A signature/DENY hit scores
  the attack **DETECTED**; a plain session-log ALLOW is attached to the SUCCESS
  verdict as a policy *reference* (telemetry), not a detection. GUI: "Appliance
  log…" button.
- **Zero-config IPS-signature modules** (no creds/infra, just `curl` + a web
  port — grade the appliance's IPS/WAF): `apache_41773`, `log4shell`,
  `web_ips_sigs` (SQLi/XSS/cmd-inj/webshell/Shellshock battery → NGWAF),
  `struts2_ognl` (CVE-2017-5638 → NGWAF "struts2 injection"). The lab appliance is
  a Sangfor **NGAF** (NGFW+NGWAF+Botnet+gateway-AV+Anti-DoS); map any new IPS
  module to a real engine before adding it (e.g. EICAR-over-HTTP is NOT added —
  gateway AV scans responses, not our inbound request).
- Every run also writes a shareable **`report.html`**, and the preflight result is
  stored in `summary.json` (`ev.meta["preflight"]`), not just `run.log`.

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
