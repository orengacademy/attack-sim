#!/usr/bin/env bash
# create-dc.sh — stand up the vulnerable Windows AD DC as a QEMU/KVM (libvirt) VM.
#
#   ⚠ LAB ONLY. Deliberately-vulnerable AD. Keep it on an isolated network.
#
# This is the THIRD Windows alternative, alongside:
#   - deploy/windows/Vagrantfile          (VirtualBox)
#   - deploy/cloud/{aws,azure,gcp}/        (cloud Terraform)
# It matches how a libvirt host already runs Windows (q35 + OVMF/UEFI + virtio,
# on the libvirt 'default' NAT network) and reuses the SAME lab definition,
# deploy/windows/provision.ps1 (+ provision_cloud.ps1 for the post-reboot pass).
#
# Two modes:
#   IMPORT an existing Windows (qcow2) image — fastest, matches a host that
#   already has one (e.g. win2019-do.qcow2):
#       sudo deploy/windows/qemu/create-dc.sh --disk /var/lib/libvirt/images/win2019-do.qcow2
#
#   INSTALL fresh from a Windows Server ISO (unattended via autounattend.xml —
#   needs your ISO + the virtio-win ISO; best-effort, see README):
#       sudo deploy/windows/qemu/create-dc.sh --iso /path/Windows_Server_2022.iso \
#            --virtio /var/lib/libvirt/images/virtio-win.iso
#
#   Tear down:
#       sudo deploy/windows/qemu/create-dc.sh --destroy [--purge]
#
# libvirt's SYSTEM session (qemu:///system) needs root — run with sudo.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WINDIR="$(cd "$HERE/.." && pwd)"               # deploy/windows

NAME="${WIN_NAME:-mygovnet-dc}"
RAM="${WIN_RAM:-6144}"                          # MiB
VCPUS="${WIN_VCPUS:-4}"
NET="${WIN_NET:-default}"                       # libvirt NAT network
OSVARIANT="${WIN_OSVARIANT:-win2k19}"           # override: WIN_OSVARIANT=win2k22
DISK_SIZE="${WIN_DISK_SIZE:-60G}"
IMG_DIR="${WIN_IMG_DIR:-/var/lib/libvirt/images}"

DISK="" ; ISO="" ; VIRTIO="" ; ACTION="" ; PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --disk)    DISK="$2"; shift 2 ;;
    --iso)     ISO="$2"; ACTION=install; shift 2 ;;
    --virtio)  VIRTIO="$2"; shift 2 ;;
    --name)    NAME="$2"; shift 2 ;;
    --ram)     RAM="$2"; shift 2 ;;
    --vcpus)   VCPUS="$2"; shift 2 ;;
    --network) NET="$2"; shift 2 ;;
    --destroy) ACTION=destroy; shift ;;
    --purge)   PURGE=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$ACTION" ] || ACTION=import   # default: import an existing --disk

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

VIRSH="virsh -c qemu:///system"
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1 (install libvirt/virtinst)"; }
need virsh; need virt-install

uefi_arg() {
  # Prefer the explicit firmware feature; older virt-install uses --boot uefi.
  if virt-install --boot help 2>/dev/null | grep -qi uefi; then echo "--boot uefi"; else echo "--boot loader.readonly=no"; fi
}

do_destroy() {
  log "Destroying domain '$NAME'…"
  $VIRSH destroy "$NAME" 2>/dev/null || true
  $VIRSH undefine "$NAME" --nvram 2>/dev/null || $VIRSH undefine "$NAME" 2>/dev/null || true
  if [ "$PURGE" -eq 1 ]; then
    rm -f "$IMG_DIR/$NAME.qcow2" 2>/dev/null && log "removed $IMG_DIR/$NAME.qcow2" || true
    rm -f "$IMG_DIR/$NAME-unattend.iso" 2>/dev/null || true
  fi
  log "Done."
}

common_args() {
  # Shared virt-install args: q35 + host CPU (Hyper-V-friendly) + guest agent + VNC.
  # Disk bus + NIC model are set per mode (virtio for an existing image that has
  # the drivers; SATA/e1000e for a fresh install so Windows Setup needs none).
  echo "--name $NAME --memory $RAM --vcpus $VCPUS --cpu host-passthrough \
        --machine q35 $(uefi_arg) --os-variant $OSVARIANT \
        --graphics vnc,listen=127.0.0.1 --video qxl \
        --channel unix,target_type=virtio,name=org.qemu.guest_agent.0 \
        --noautoconsole"
}

do_import() {
  [ -n "$DISK" ] || die "--disk <existing-windows.qcow2> is required for import mode (or use --iso to install)"
  [ -f "$DISK" ] || die "disk image not found: $DISK"
  if $VIRSH dominfo "$NAME" >/dev/null 2>&1; then die "domain '$NAME' already exists — '--destroy' it first."; fi
  log "Importing $DISK as libvirt domain '$NAME' ($VCPUS vCPU / ${RAM}MiB, net '$NET')…"
  # existing images already carry virtio drivers -> use virtio for best performance.
  # shellcheck disable=SC2046
  virt-install $(common_args) \
    --network network="$NET",model=virtio \
    --disk path="$DISK",bus=virtio,format=qcow2 \
    --import
  post_up
}

build_unattend_iso() {
  # Bundle autounattend.xml + provision.ps1 + provision_cloud.ps1 onto a small
  # ISO that Windows Setup auto-discovers (answer file at the media root). The
  # FirstLogonCommands in autounattend.xml run provision_cloud.ps1 -> provision.ps1.
  local tmp out="$IMG_DIR/$NAME-unattend.iso"
  tmp="$(mktemp -d)"
  cp "$HERE/autounattend.xml" "$tmp/autounattend.xml"
  cp "$WINDIR/provision.ps1" "$tmp/provision.ps1"
  cp "$WINDIR/../cloud/provision_cloud.ps1" "$tmp/provision_cloud.ps1"
  if command -v genisoimage >/dev/null 2>&1; then
    genisoimage -quiet -J -r -V OEMDRV -o "$out" "$tmp"
  else
    mkisofs -quiet -J -r -V OEMDRV -o "$out" "$tmp"
  fi
  rm -rf "$tmp"
  echo "$out"
}

do_install() {
  [ -f "$ISO" ] || die "Windows ISO not found: $ISO"
  [ -n "$VIRTIO" ] && [ ! -f "$VIRTIO" ] && die "virtio-win ISO not found: $VIRTIO"
  if $VIRSH dominfo "$NAME" >/dev/null 2>&1; then die "domain '$NAME' already exists — '--destroy' it first."; fi
  local disk="$IMG_DIR/$NAME.qcow2"
  log "Creating ${DISK_SIZE} system disk at $disk…"
  qemu-img create -f qcow2 "$disk" "$DISK_SIZE" >/dev/null
  local unattend; unattend="$(build_unattend_iso)"
  log "Starting UNATTENDED install from $ISO (answer file: $unattend)…"
  warn "Unattended Windows install is best-effort — if Setup stops for input,"
  warn "connect to the VNC console (virt-viewer/vinagre to 127.0.0.1:0) and finish it."
  local virtio_disk=""
  [ -n "$VIRTIO" ] && virtio_disk="--disk path=$VIRTIO,device=cdrom"
  # SATA system disk + e1000e NIC = natively supported by Windows Setup, so no
  # storage/network driver injection is needed to complete an unattended install.
  # (Attach the virtio-win ISO with --virtio only if you want to switch to virtio
  # afterwards for performance.)
  # shellcheck disable=SC2046
  virt-install $(common_args) \
    --network network="$NET",model=e1000e \
    --disk path="$disk",bus=sata,format=qcow2 \
    --disk path="$ISO",device=cdrom,boot_order=1 \
    $virtio_disk \
    --disk path="$unattend",device=cdrom
  post_up
}

post_up() {
  log "Domain '$NAME' started. Console: VNC on 127.0.0.1 (virt-viewer -c qemu:///system $NAME)."
  log "Waiting for the QEMU guest agent to report an IP (Ctrl-C to stop waiting)…"
  local ip="" tries=0
  while [ $tries -lt 60 ]; do
    ip="$($VIRSH domifaddr "$NAME" --source agent 2>/dev/null \
          | awk '/ipv4/ && $4 !~ /^127\./ {sub(/\/.*/,"",$4); print $4; exit}')" || true
    [ -n "$ip" ] && break
    sleep 5; tries=$((tries+1))
  done
  echo
  if [ -n "$ip" ]; then
    log "Guest IP: $ip"
  else
    warn "No IP yet (install may still be running). Later: $VIRSH domifaddr $NAME --source agent"
    ip="<dc-ip>"
  fi
  cat <<EOF

$(log "Windows AD DC VM is up.")
  Lab: domain lab.local, Administrator/Passw0rd!, kerberoast=svc_sql, asrep=svc_asrep.
  If you imported a NOT-yet-provisioned image, run the lab seeding on the DC:
      (on the DC)  powershell -ExecutionPolicy Bypass -File provision.ps1   # twice (reboots once)
  Point the harness at it:
      HARNESS_DOMAIN=lab.local HARNESS_DC_USER=Administrator HARNESS_DC_PASS='Passw0rd!' \\
        python3 cli.py --target $ip --only dcsync,psexec,samaccountname_spoof,kerberoast,ldap_null_bind --confirm-roe
  Tear down:  sudo $0 --destroy --purge
EOF
}

case "$ACTION" in
  destroy) do_destroy ;;
  install) do_install ;;
  import)  do_import ;;
esac
