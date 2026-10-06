# Lab target inventory — MyGovNet (ORG2026-70)

> **Controlled dummy lab.** Throwaway lab hosts + creds only (never real-world
> secrets), recorded per the repo convention (see CLAUDE.md → "Operator files").
> Passwords are still redacted (`***`) from all evidence at runtime.

**▶ Active site for this engagement: `KVDC`.** The battery runs *from* the KVDC
attacker machine *against* the KVDC Windows DCs (first table below).

Every site provides two postures — run the **same** battery against each and compare
per module (CLAUDE.md → "Verdict model"):

- **Whitebox** = allow-all baseline path → attacks **SHOULD pass** (proves the attack
  works). Run with `--mode whitebox`.
- **Blackbox** = through the SD-WAN with the real policy → the control blocks/detects.
  Run with `--mode blackbox`.
- `SUCCESS` (whitebox) + `BLOCKED`/`NO-SERVICE` (blackbox) on the same module = **the
  control works.**

Each posture has an **attacker machine** (where attack-sim runs) and a **Windows 2019
DC** (the target the modules authenticate to with `Administrator` / `NewPass123!`).

| Port mapping | Sites |
|---|---|
| SMB **445→4445**, RPC **135→1135** (cloud NAT — set `--cloud`) | Cloud |
| default **445 / 135** (no NAT — `--no-cloud`) | IPDC, KVDC |

---

## KVDC  — ACTIVE (on-prem, default 445/135)

| Posture | Role | IP | Login | Notes |
|---|---|---|---|---|
| **Whitebox** | Attacker (runs sim) | `10.38.98.13` | `kali` / `kali` | allow-all path |
| **Whitebox** | Windows 2019 DC (target) | `10.38.98.12` | `Administrator` / `NewPass123!` | 445/135 |
| **Blackbox** | Attacker (runs sim) | `10.38.98.15` | `kali` / `kali` | through the SD-WAN |
| **Blackbox** | Windows 2019 DC (target) | `10.38.98.14` | `Administrator` / `NewPass123!` | 445/135 |

Run (from the KVDC attacker box, creds remembered after the first run):
```bash
# whitebox baseline (from 10.38.98.13):
python3 cli.py --target 10.38.98.12 --mode whitebox --no-cloud --all \
    --dc-user Administrator --dc-pass 'NewPass123!' --domain lab.local --confirm-roe
# blackbox through the SD-WAN (from 10.38.98.15):
python3 cli.py --target 10.38.98.14 --mode blackbox --no-cloud --all \
    --dc-user Administrator --dc-pass 'NewPass123!' --domain lab.local --confirm-roe
```

### KVDC — verification (2026-10-06, from central host `10.41.241.18` via gateway)

| Target | Posture | Module | Result | Note |
|---|---|---|---|---|
| `10.38.98.12` | whitebox | `ldap_null_bind` | **SUCCESS** | 445/135/389/88 open; LDAP/Kerberos/SMB reachable + creds OK |
| `10.38.98.12` | whitebox | `dcsync` | **BLOCKED** | SMB(445)+EPM(135) connect, but the DRSUAPI **dynamic high RPC port** is refused from this segment |
| `10.38.98.14` | blackbox | `dcsync` | **NO-SERVICE** | SMB(445) closed (service down / SD-WAN segmentation) |

**Run RPC/SMB-exec modules (`dcsync`/`psexec`/`wmiexec`) from the on-segment KVDC
attacker box** — whitebox `10.38.98.13`, blackbox `10.38.98.15`. From the central host
only 445/135/389/88 are forwarded, not the ephemeral RPC range DRSUAPI/DCE-RPC need, so
those modules can't complete here (BLOCKED on the dynamic port). Non-RPC modules
(LDAP/Kerberos/web/DoS) verify fine from anywhere that can reach the DC.

## IPDC  (on-prem, default 445/135)

| Posture | Role | IP | Login |
|---|---|---|---|
| **Whitebox** | Attacker (runs sim) | `10.38.98.133` | `kali` / `kali` |
| **Whitebox** | Windows 2019 DC (target) | `10.38.98.132` | `Administrator` / `NewPass123!` |
| **Blackbox** | Attacker (runs sim) | `10.38.98.135` | `kali` / `kali` |
| **Blackbox** | Windows 2019 DC (target) | `10.38.98.134` | `Administrator` / `NewPass123!` |

## Cloud  (DigitalOcean, SMB 445→4445 / RPC 135→1135)

On cloud the attacker sim and the DC are **co-located on one host** (dual-role); the
`oreng` login (web/SSH on **:8181**) is how you reach the attacker sim, `Administrator`
is the DC target cred the modules use.

| Posture | Role | IP | Login |
|---|---|---|---|
| **Whitebox** | Attacker (runs sim) | `159.223.35.108` | `oreng` @ :8181 / `Or3nG@G17n-1337!` |
| **Whitebox** | Windows 2019 DC (target) | `159.223.35.108` | `Administrator` / `NewPass123!` |
| **Blackbox** | Attacker (runs sim) | `167.71.222.169` | `oreng` @ :8181 / `Or3nG@G17n-1337!` |
| **Blackbox** | Windows 2019 DC (target) | `167.71.222.169` | `Administrator` / `NewPass123!` |

Run (cloud, NAT'd ports):
```bash
# whitebox baseline:
python3 cli.py --target 159.223.35.108 --mode whitebox --cloud --all --confirm-roe
# blackbox through the SD-WAN:
python3 cli.py --target 167.71.222.169 --mode blackbox --cloud --all --confirm-roe
```

---

Notes:
- The harness **remembers** per-target config (`cloud`/ports/creds/`mode`) in
  `.target_memory.json` after the first run, so later runs can omit the flags.
- On-prem DCs (IPDC/KVDC) answer SMB/RPC on **445/135** directly — do **not** pass
  `--cloud` for them. Only the Cloud DCs are NAT'd to 4445/1135.
- `kerberoast`/`nopac`/`samaccountname_spoof` need an **unpatched** DC;
  `dcsync`/`psexec`/`wmiexec` need the `impacket` library (see CLAUDE.md).
