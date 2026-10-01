#!/usr/bin/env bash
# setup_all.sh — ONE-SHOT lab bring-up on a fresh Linux VM (any mainstream distro).
#
#   ⚠ LAB ONLY. Stands up DELIBERATELY VULNERABLE services. Run only on an
#   isolated, authorised host you own, inside scope/RoE. Never expose to the
#   internet unfirewalled. Tear down after the engagement (--teardown).
#
# Does everything the README's "Deploying the vulnerable target(s)" section does,
# automated, and idempotent:
#   1. installs Docker + compose plugin if missing (apt, or get.docker.com, or
#      the native pacman/zypper/apk package)
#   2. runs setup_target.sh   (SSH weak user, anon FTP, SNMP public)
#   3. docker compose up -d    (Apache 41773 :80, Log4Shell :8080, OpenLDAP :389)
#   4. (optional) bootstrap.py to install the ATTACKER tooling too, so one box can
#      be both target and tester for a self-test.
#   5. (optional, --with-windows) install Vagrant + VirtualBox and boot the
#      vulnerable Windows AD DC VM (deploy/windows) — Target #2, in one command.
#   6. prints the ready-to-run cli.py self-test.
#
# TWO targets: this Linux HOST becomes Target #1 (SSH/FTP/SNMP + web CVE
# containers, configured in place — no VM). The Windows AD DC is Target #2, a
# SEPARATE VM brought up by Vagrant (needs a provider + hardware virtualization).
#
# Usage:
#   sudo deploy/setup_all.sh                 # Linux target services only
#   sudo deploy/setup_all.sh --with-tools    # also install attacker tooling (bootstrap.py)
#   sudo deploy/setup_all.sh --with-windows  # ALSO boot the Windows AD DC VM (Vagrant+VirtualBox)
#   sudo deploy/setup_all.sh --teardown      # remove everything (incl. the Windows VM)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
WITH_TOOLS=0
WITH_WINDOWS=0
ACTION=setup
for a in "$@"; do
  case "$a" in
    --with-tools) WITH_TOOLS=1 ;;
    --with-windows) WITH_WINDOWS=1 ;;
    --teardown|-d) ACTION=teardown ;;
    *) echo "unknown arg: $a"; exit 2 ;;
  esac
done

log() { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }; }

compose() {
  # prefer the v2 plugin ("docker compose"); fall back to v1 ("docker-compose")
  if docker compose version >/dev/null 2>&1; then docker compose "$@";
  elif command -v docker-compose >/dev/null 2>&1; then docker-compose "$@";
  else return 127; fi
}

start_docker() {
  # systemd on most; OpenRC on Alpine. Best-effort — don't abort the run.
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl enable --now docker 2>/dev/null || true
  elif command -v rc-service >/dev/null 2>&1; then
    rc-update add docker default 2>/dev/null || true; rc-service docker start 2>/dev/null || true
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && compose version >/dev/null 2>&1; then
    log "Docker + compose already present."; return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    log "Installing Docker Engine + compose plugin (apt)…"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y -q
    # docker.io + the distro compose plugin is enough for this lab (no docker
    # apt repo needed). docker-compose-v2 provides "docker compose".
    apt-get install -y -q docker.io docker-compose-v2 || \
      apt-get install -y -q docker.io docker-compose
  elif command -v pacman >/dev/null 2>&1; then
    log "Installing Docker + compose (pacman)…"
    pacman -Sy --noconfirm docker docker-compose
  elif command -v zypper >/dev/null 2>&1; then
    log "Installing Docker + compose (zypper)…"
    zypper --non-interactive install docker docker-compose
  elif command -v apk >/dev/null 2>&1; then
    log "Installing Docker + compose (apk)…"
    apk add --no-cache docker docker-cli-compose
  elif command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    # dnf/yum (RHEL/Fedora/CentOS/Rocky/Alma) and the rest: Docker's official
    # convenience script installs docker-ce + the compose plugin everywhere it
    # supports. Falls back to wget if curl is absent.
    log "Installing Docker via get.docker.com convenience script…"
    if command -v curl >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sh;
    else wget -qO- https://get.docker.com | sh; fi
  else
    warn "Could not auto-install Docker on this distro — install Docker + the"
    warn "compose plugin manually, then re-run. (Host SSH/FTP/SNMP still set up.)"
    return 1
  fi
  start_docker
}

install_vagrant() {
  # Vagrant + VirtualBox for the Windows DC VM. apt is the common case; other
  # distros vary too much to auto-install reliably, so point the user at docs.
  if command -v vagrant >/dev/null 2>&1 && command -v VBoxManage >/dev/null 2>&1; then
    log "Vagrant + VirtualBox already present."; return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    log "Installing Vagrant + VirtualBox (apt)…"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y -q
    apt-get install -y -q virtualbox vagrant || return 1
  else
    warn "Auto-install of Vagrant+VirtualBox is only wired for apt. Install them"
    warn "manually (vagrantup.com + virtualbox.org), then: cd deploy/windows && vagrant up"
    return 1
  fi
}

windows_up() {
  # Boot the vulnerable Windows AD DC VM (Target #2). Three backends:
  #   - libvirt/QEMU (preferred when present + a disk/ISO is given)
  #   - VirtualBox/Vagrant (default, downloads a Windows box)
  if ! grep -qiE 'vmx|svm' /proc/cpuinfo 2>/dev/null; then
    warn "No hardware virtualization (vmx/svm) detected on this host — a Windows VM"
    warn "likely won't boot here (basic cloud instances lack nested virt). Skipping."
    return 1
  fi
  # Prefer QEMU/libvirt when it's installed AND the user pointed us at an image
  # or ISO (we can't conjure Windows). Env: WIN_QEMU_DISK=<qcow2> or WIN_QEMU_ISO=<iso>.
  if command -v virsh >/dev/null 2>&1 && command -v virt-install >/dev/null 2>&1 \
     && { [ -n "${WIN_QEMU_DISK:-}" ] || [ -n "${WIN_QEMU_ISO:-}" ]; }; then
    log "Using QEMU/libvirt for the Windows DC…"
    if [ -n "${WIN_QEMU_DISK:-}" ]; then
      bash "$HERE/windows/qemu/create-dc.sh" --disk "$WIN_QEMU_DISK" \
        || { warn "QEMU create-dc.sh failed — see output."; return 1; }
    else
      bash "$HERE/windows/qemu/create-dc.sh" --iso "$WIN_QEMU_ISO" \
        ${WIN_QEMU_VIRTIO:+--virtio "$WIN_QEMU_VIRTIO"} \
        || { warn "QEMU create-dc.sh failed — see output."; return 1; }
    fi
    return 0
  fi
  if command -v virsh >/dev/null 2>&1; then
    log "libvirt is present — for the QEMU path, set WIN_QEMU_DISK=<qcow2> (or"
    log "WIN_QEMU_ISO=<windows.iso>) and re-run; see deploy/windows/qemu/README.md."
    log "Falling back to VirtualBox/Vagrant for now…"
  fi
  install_vagrant || return 1
  log "Booting the Windows AD DC VM (first run downloads a ~5GB box; needs ~4GB RAM)…"
  ( cd "$HERE/windows" && vagrant up ) || { warn "vagrant up failed — see output."; return 1; }
  log "Windows DC VM up at 192.168.56.10 (domain lab.local, Administrator/Passw0rd!)."
}

teardown() {
  need_root
  warn "Tearing down lab…"
  ( cd "$HERE" && compose down -v 2>/dev/null || true )
  bash "$HERE/setup_target.sh" --teardown || true
  if command -v vagrant >/dev/null 2>&1 && [ -d "$HERE/windows/.vagrant" ]; then
    warn "Destroying the Windows AD DC VM…"
    ( cd "$HERE/windows" && vagrant destroy -f 2>/dev/null || true )
  fi
  log "Done. (Docker Engine left installed; remove with: apt-get remove --purge docker.io)"
}

setup() {
  need_root
  cat <<'BANNER'
==========================================================================
  ⚠  ONE-SHOT LAB BRING-UP — INTENTIONALLY VULNERABLE SERVICES (LAB ONLY)
     Isolate this host. Do not expose to the internet unfirewalled.
==========================================================================
BANNER
  DOCKER_OK=1
  install_docker || DOCKER_OK=0
  log "Configuring host services (SSH/FTP/SNMP)…"
  bash "$HERE/setup_target.sh"
  if [ "$DOCKER_OK" -eq 1 ] && compose version >/dev/null 2>&1; then
    log "Starting containerised web/dir services (Apache/Log4Shell/OpenLDAP)…"
    ( cd "$HERE" && compose up -d ) || warn "docker compose up failed — host services are still configured."
  else
    warn "Docker unavailable — skipping web/dir containers (Apache/Log4Shell/OpenLDAP)."
    warn "Host SSH/FTP/SNMP are configured; install Docker + re-run for the web CVEs."
  fi
  if [ "$WITH_TOOLS" -eq 1 ]; then
    log "Installing attacker tooling (bootstrap.py)…"
    python3 "$REPO/bootstrap.py" || warn "bootstrap.py had issues — see output."
  fi
  log "Waiting for containers to settle…"; sleep 5
  ( cd "$HERE" && compose ps || true )

  WIN_NOTE="  Windows AD DC (Target #2): not requested. Add --with-windows, or:
    cd deploy/windows && vagrant up"
  if [ "$WITH_WINDOWS" -eq 1 ]; then
    log "Bringing up the Windows AD DC VM (Target #2)…"
    if windows_up; then
      WIN_NOTE="  Windows AD DC (Target #2): UP at 192.168.56.10 (lab.local, Administrator/Passw0rd!).
    Test it: cd \"$REPO\" && HARNESS_DOMAIN=lab.local HARNESS_DC_USER=Administrator \\
      HARNESS_DC_PASS='Passw0rd!' python3 cli.py --target 192.168.56.10 \\
      --only kerberoast,kerberos_asrep,dcsync,psexec,wmiexec,petitpotam --confirm-roe"
    else
      WIN_NOTE="  Windows AD DC (Target #2): NOT started (see warnings above). Retry on a host
    with hardware virtualization: cd deploy/windows && vagrant up"
    fi
  fi

  cat <<EOF

$(log "Lab ready.")
  Linux target (Target #1) — self-test from THIS box (confirms the lab works):
    cd "$REPO" && python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe

  USS scope only (the attack-simulation boundary set):
    cd "$REPO" && python3 cli.py --target 127.0.0.1 --attack-sim --confirm-roe

$WIN_NOTE

  Teardown (incl. the Windows VM):
    sudo deploy/setup_all.sh --teardown
EOF
}

case "$ACTION" in
  teardown) teardown ;;
  *) setup ;;
esac
