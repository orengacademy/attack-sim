# Cloud & KVDC deployment (Windows AD + reverse direction)

> ⚠️ **LAB ONLY.** These stand up **deliberately-vulnerable** targets. Lock every
> one to your tester source IPs (NSG/Security-Group **and** the harness
> `HARNESS_ALLOWLIST`), keep them off `0.0.0.0/0`, and **tear down** after the
> window. A vulnerable DC exposed to the internet is a real compromise.

## Which tool for which environment?

**Vagrant is for the local bench only.** For KVDC / cloud, decouple *VM delivery*
from *guest config* and reuse the one lab definition (`../windows/provision.ps1`):

| Environment | VM delivery | Guest config |
|---|---|---|
| Local bench | Vagrant + VirtualBox (`../windows/`) | `provision.ps1` (2 passes) |
| KVDC (on-prem hypervisor) | Terraform vSphere/Hyper-V/Nutanix, or a Windows template clone | `provision_cloud.ps1` via WinRM/guest-ops |
| **Cloud (Azure — best for a DC)** | **`azure/` Terraform here** | `provision_cloud.ps1` (Custom Script Extension) |
| **Cloud (AWS)** | **`aws/` Terraform here** | `provision_cloud.ps1` (EC2 `user_data`) |
| Cloud (GCP) | Terraform `google_compute_instance` + `windows-startup-script-ps1` | `provision_cloud.ps1` (same pattern as AWS) |

`provision_cloud.ps1` wraps the unchanged `provision.ps1`: it registers a
self-removing startup task so the **promote → reboot → seed** two-pass flow
completes unattended (no second manual `vagrant provision`).

## Azure (Terraform)

```bash
cd deploy/cloud/azure
cp terraform.tfvars.example terraform.tfvars   # set tester_cidrs + admin_password
terraform init
terraform apply
terraform output harness_hint                  # how to point the harness at the DC
```

Creates: RG, VNet/subnet, an **NSG locked to `tester_cidrs`** (AD/mgmt ports only),
a Windows Server 2022 VM, and a Custom Script Extension that runs
`provision_cloud.ps1`. Give it ~15–20 min for the promo, reboot and seed to finish.
Prefer `create_public_ip = false` and reach it over VPN/ExpressRoute.

Destroy when done:
```bash
terraform destroy
```

## AWS (Terraform)

```bash
cd deploy/cloud/aws
cp terraform.tfvars.example terraform.tfvars   # set vpc_id, subnet_id, tester_cidrs, key_name
terraform init && terraform apply
terraform output harness_hint
```

Launches a Windows Server 2022 EC2 instance whose `user_data` base64-embeds and runs
the same `provision.ps1` + `provision_cloud.ps1` (no S3 needed), with a security group
locked to `tester_cidrs`. Retrieve the local admin password with your key pair
(`terraform output windows_password_data`); the **domain** Administrator password is
the lab weak password from `provision.ps1`. `terraform destroy` when done.

## The ISP 139/445 constraint (cloud path)

The cloud uplink blocks **139/445**, so SMB-based AD attacks can't cross it:

| Runs over the ISP path | Ports | Works to cloud? |
|---|---|---|
| `kerberoast` | 88, 389 | ✅ |
| `kerberos_asrep` | 88 | ✅ |
| `ldap_null_bind` | 389 | ✅ |
| `dcsync` | 445, 135 | ❌ (run from an **intra-cloud** foothold) |
| `psexec`, `petitpotam`, `eastwest_lateral` | 445 | ❌ (intra-cloud, or via `socks_pivot` over 443) |

A `BLOCKED` on 445 to the cloud DC is the **ISP**, not the SD-WAN — don't score it
as an SD-WAN control. Test 445-dependent attacks from a foothold **inside** the
cloud VNet (assumed-breach #2), or tunnel them over 443 (`socks_pivot`).

## Reverse direction (B → A / server-initiated)

Test the "and vice versa" path from a DC/cloud foothold two ways:

- **Full harness**, pinned to the DC's egress interface:
  ```bash
  python3 cli.py --target <user-zone-or-public> --attack-sim --direction b2a \
    --source <DC_interface_ip> --confirm-roe
  ```
- **Standalone one-file drop** (no repo needed) on a foothold you can't install on:
  ```bash
  scp additional/reverse_runner.py foothold:/tmp/
  ssh foothold 'python3 /tmp/reverse_runner.py --vps <your_vps> --source <DC_ip> --json'
  ```
  A server VLAN should be default-deny outbound — any open egress path it finds is a
  finding.
