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
#   5. prints the ready-to-run cli.py self-test.
#
# Usage:
#   sudo deploy/setup_all.sh              # target services only
#   sudo deploy/setup_all.sh --with-tools # also install attacker tooling (bootstrap.py)
#   sudo deploy/setup_all.sh --teardown   # remove everything
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
WITH_TOOLS=0
ACTION=setup
for a in "$@"; do
  case "$a" in
    --with-tools) WITH_TOOLS=1 ;;
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

teardown() {
  need_root
  warn "Tearing down lab…"
  ( cd "$HERE" && compose down -v 2>/dev/null || true )
  bash "$HERE/setup_target.sh" --teardown || true
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
  cat <<EOF

$(log "Lab ready.")
  Self-test from THIS box (white-box baseline — confirms the lab works):
    cd "$REPO" && python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe

  USS scope only (the attack-simulation boundary set):
    cd "$REPO" && python3 cli.py --target 127.0.0.1 --attack-sim --confirm-roe

  Teardown:
    sudo deploy/setup_all.sh --teardown
EOF
}

case "$ACTION" in
  teardown) teardown ;;
  *) setup ;;
esac
