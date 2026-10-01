# Deploying the vulnerable target(s)

> ⚠️ **LAB ONLY.** These scripts deliberately configure **weak/vulnerable**
> services. Deploy only on an **isolated, authorised** target you own (the
> MyGovNet BAS droplet), inside your scope/RoE. **Never** expose it to the open
> internet without a firewall/allowlist restricting it to your tester IPs, and
> **tear it down** after the engagement. You are responsible for keeping it
> contained.

Two target types:

| Target | Provides | How |
|--------|----------|-----|
| **Linux services** (FTP/SSH/SNMP/LDAP + web CVEs + HTTPS 443) | ftp_anonymous, ssh_brute, snmp_brute, ldap_null_bind, apache_41773, log4shell, tls_carrier, ja3_mimicry, l7_enforce_443, http_smuggling, waf_evasion, exposed_mgmt_api, floods, segmentation, egress | `setup_target.sh` + `docker compose` |
| **Windows AD DC** (Kerberos/LDAP/SMB) | kerberoast, kerberos_asrep, dcsync, psexec, wmiexec, petitpotam, nopac·samaccountname_spoof (unpatched DC only) | **Vagrant** (`deploy/windows/`) |

The Debian droplet can host the Linux side; the **Windows/AD attacks need a real
Windows DC** (PsExec/PetitPotam are Windows-only) — use the Vagrant box (local bench),
the **[cloud/KVDC Terraform](cloud/README.md)** (Azure module reusing `provision.ps1`),
or point the harness's AD modules at a separate Windows DC IP.

## Fastest path: one command (any mainstream Linux)

Distro-agnostic — detects apt/dnf/yum/pacman/zypper/apk (and installs Docker via
the native package or `get.docker.com`):

```bash
sudo deploy/setup_all.sh                # Linux target: Docker (if missing) + host services + containers
sudo deploy/setup_all.sh --with-tools   # also install the attacker tooling (bootstrap.py)
sudo deploy/setup_all.sh --with-windows # ALSO boot the Windows AD DC VM (Vagrant+VirtualBox)
sudo deploy/setup_all.sh --teardown     # remove everything (incl. the Windows VM)
```

**Two targets, two mechanisms.** The **Linux host itself** becomes Target #1 —
`setup_all.sh` configures SSH/FTP/SNMP and the web-CVE containers *in place* (no
VM). The **Windows AD DC** is Target #2, a *separate VM*: `--with-windows` (or `cd
deploy/windows && vagrant up`) uses **Vagrant + VirtualBox** to download a Windows
Server 2022 box (~5 GB) and boot a 4 GB VM on a host-only net (`192.168.56.10`) —
so the host needs hardware virtualization (VT-x/AMD-V); `--with-windows` checks for
it and skips with a warning if absent (e.g. a basic cloud instance without nested
virt — use the cloud Terraform there instead).

Then self-test from the box: `python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe`.
The manual, step-by-step equivalent is below.

---

## 1. Linux target (any distro)

```bash
sudo ./deploy/setup_target.sh            # host services: SSH lab user, FTP anon, SNMP public
cd deploy && docker compose up -d        # web CVEs + LDAP + HTTPS-443 (Apache :80, Log4Shell :8080, OpenLDAP :389, https-lab :443)
```

The `https-lab` container (nginx on **:443**, self-signed cert generated in-container
on first start) gives the 443 boundary modules a real target — without it they
report `NO-SERVICE`. With it: `tls_carrier` / `ja3_mimicry` complete handshakes,
`exposed_mgmt_api` finds the deliberately-exposed mgmt paths (`/actuator`, `/.git/HEAD`,
`/.env`, `/server-status`, …), and `l7_enforce_443` / `http_smuggling` / `waf_evasion`
have an endpoint to probe (they report `REVIEW` against a plain app — point
`published_app_url` at your real WAF'd app to exercise them fully). First start needs
outbound internet (the container `apk add`s openssl to mint the cert).

`setup_target.sh` auto-writes a git-ignored `credentials.env` pointing `ssh_brute`
at the lab SSH user (`labadmin`/`Passw0rd!`), so **no manual export is needed** —
the self-test below shows `ssh_brute` SUCCESS out of the box. (If a `credentials.env`
already exists it's left untouched; export `HARNESS_DC_USER=labadmin
HARNESS_DC_PASS='Passw0rd!'` yourself in that case.)

Verify from the box itself (bypasses any ISP/SD-WAN path issues):

```bash
python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe
```

`SUCCESS` per module = that vuln/service is genuinely up. `NO-SERVICE`/`AUTH-FAILED`
= not really up (fix the lab, not a control result).

## 2. Windows AD DC (Vagrant)

On a host with Vagrant + a provider (VirtualBox/libvirt/Hyper-V):

```bash
cd deploy/windows
vagrant up            # ONE command: install AD DS, promote, reboot, seed accounts
```

A single `vagrant up` now runs both provisioning passes automatically (Vagrant
reboots the guest between them; `provision.ps1` waits for AD DS to come up before
seeding). Needs Vagrant 2.2.0+ and a provider (VirtualBox by default).

It creates a domain with a **Kerberoastable** SPN account, an **AS-REP-roastable**
(no-preauth) account, weak admin creds for DCSync/PsExec/WMIExec, and sets
`ms-DS-MachineAccountQuota=10`. ⚠ `nopac`/`samaccountname_spoof` additionally need an
**unpatched** DC (pre-Nov-2021); on a patched build those two correctly fail. Point
the harness at the DC:

```bash
export HARNESS_DOMAIN=lab.local HARNESS_DC_USER=Administrator HARNESS_DC_PASS='<from Vagrantfile>'
python3 cli.py --target <DC_IP> --only kerberoast,kerberos_asrep,dcsync,psexec,wmiexec,petitpotam,nopac,samaccountname_spoof --confirm-roe
```

For a fuller, battle-tested AD lab, consider **GOAD** (Game of Active Directory,
`github.com/Orange-Cyberdefense/GOAD`) — same idea, many more misconfigurations.

## Teardown

```bash
cd deploy && docker compose down -v
cd deploy/windows && vagrant destroy -f
# and on the droplet, revert setup_target.sh services if keeping the box:
sudo ./deploy/setup_target.sh --teardown
```
