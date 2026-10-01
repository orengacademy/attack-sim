# Windows AD DC via QEMU/KVM (libvirt)

The **third** way to stand up the vulnerable Windows AD DC, next to the VirtualBox
`Vagrantfile` (one dir up) and the cloud Terraform (`deploy/cloud/`). Use this when
your host runs **libvirt/QEMU** rather than VirtualBox. It mirrors a typical libvirt
Windows VM — **q35 + OVMF/UEFI + virtio**, on the libvirt `default` NAT network —
and reuses the same lab definition (`../provision.ps1` + `../../cloud/provision_cloud.ps1`).

> ⚠ **LAB ONLY** — deliberately-vulnerable AD. Keep it on an isolated network and
> tear it down after the engagement. libvirt's system session needs root → `sudo`.

## Requirements
`libvirt` + `qemu-kvm` + `virtinst` (`virt-install`, `virsh`) and `genisoimage`
(or `mkisofs`/`xorriso`). On Debian/Ubuntu:
```bash
sudo apt-get install -y qemu-kvm libvirt-daemon-system virtinst genisoimage ovmf
```

## Two modes

### A. Import an existing Windows image (fastest)
If you already have a Windows qcow2 (e.g. one this host runs), define + boot it:
```bash
sudo deploy/windows/qemu/create-dc.sh --disk /var/lib/libvirt/images/win2019-do.qcow2
```
virtio disk + NIC (the image already has the drivers). If it isn't provisioned yet,
run `provision.ps1` on the DC (twice — it reboots once).

### B. Fresh unattended install from a Windows Server ISO
```bash
sudo deploy/windows/qemu/create-dc.sh \
  --iso /path/Windows_Server_2022.iso \
  --virtio /var/lib/libvirt/images/virtio-win.iso      # optional (perf only)
```
`create-dc.sh` bundles `autounattend.xml` + `provision.ps1` + `provision_cloud.ps1`
onto an `OEMDRV` ISO that Windows Setup auto-discovers; at first logon it runs the
provisioning (install AD DS → promote → reboot → seed accounts). The install disk
is **SATA** and the NIC **e1000e**, both natively supported by Windows Setup, so no
driver injection is needed.

> **Best-effort:** unattended Windows installs are fiddly. Edit `autounattend.xml`
> for your ISO's **product key** and **image name** (`dism /Get-WimInfo
> /WimFile:<iso>\sources\install.wim`). If Setup stops for input, open the console
> (`virt-viewer -c qemu:///system mygovnet-dc`) and finish it by hand.

## Common options (env or flags)
`--name` (`mygovnet-dc`) · `--ram` MiB (`6144`) · `--vcpus` (`4`) · `--network`
(`default`) · `WIN_OSVARIANT` (`win2k19`; set `win2k22` for 2022) · `--disk-size`
(`60G`, install mode).

## Lifecycle
```bash
sudo deploy/windows/qemu/create-dc.sh --disk <img.qcow2>   # import + boot
sudo deploy/windows/qemu/create-dc.sh --destroy            # stop + undefine
sudo deploy/windows/qemu/create-dc.sh --destroy --purge    # also delete the disk
```
The script prints the guest IP (via the QEMU guest agent) and the ready-to-run
`cli.py` command. Point the harness at that IP:
```bash
HARNESS_DOMAIN=lab.local HARNESS_DC_USER=Administrator HARNESS_DC_PASS='Passw0rd!' \
  python3 cli.py --target <dc-ip> \
  --only dcsync,psexec,samaccountname_spoof,kerberoast,ldap_null_bind --confirm-roe
```

## Notes
- Same two patched-DC caveat as the other paths: `nopac`/`samaccountname_spoof`
  need an **unpatched** DC.
- The default NAT IP (`192.168.122.x`) isn't externally reachable; bridge the VM
  or add port-forwards if you test from another host.
