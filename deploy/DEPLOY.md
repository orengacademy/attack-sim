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
| **Linux services** (FTP/SSH/SNMP/LDAP + web CVEs) | ftp_anonymous, ssh_brute, snmp_brute, ldap_null_bind, apache_41773, log4shell, floods, segmentation, egress | `setup_target.sh` + `docker compose` |
| **Windows AD DC** (Kerberos/LDAP/SMB) | kerberoast, kerberos_asrep, dcsync, psexec, petitpotam | **Vagrant** (`deploy/windows/`) |

The Debian droplet can host the Linux side; the **Windows/AD attacks need a real
Windows DC** (PsExec/PetitPotam are Windows-only) — use the Vagrant box, or point
the harness's AD modules at a separate Windows DC IP.

---

## 1. Linux target (on the Debian droplet)

```bash
sudo ./deploy/setup_target.sh            # host services: SSH lab user, FTP anon, SNMP public
cd deploy && docker compose up -d        # web CVEs + LDAP (Apache 41773 :80, Log4Shell :8080, OpenLDAP :389)
```

Then set the SSH creds the harness will try (match what setup_target.sh created):

```bash
export HARNESS_DC_USER=labadmin
export HARNESS_DC_PASS='Passw0rd!'       # or whatever you set in setup_target.sh
```

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
vagrant up            # provisions Windows Server, promotes to a DC, seeds vulnerable accounts
```

It creates a domain with a **Kerberoastable** SPN account, an **AS-REP-roastable**
(no-preauth) account, and weak admin creds for DCSync/PsExec. Point the harness at
the DC:

```bash
export HARNESS_DOMAIN=lab.local HARNESS_DC_USER=Administrator HARNESS_DC_PASS='<from Vagrantfile>'
python3 cli.py --target <DC_IP> --only kerberoast,kerberos_asrep,dcsync,psexec,petitpotam --confirm-roe
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
