#!/usr/bin/env bash
# setup_target.sh — configure DELIBERATELY WEAK Linux services on the BAS target.
#
#   ⚠ LAB ONLY. Isolated, authorised target you own, inside scope/RoE. Never expose
#   to the open internet unfirewalled. Tear down after the engagement.
#
# Configures the host-level services the harness tests:
#   - SSH  : a lab user with a weak password       (ssh_brute)
#   - FTP  : vsftpd with anonymous login enabled   (ftp_anonymous)
#   - SNMP : snmpd with the 'public' community      (snmp_brute)
# Web CVEs (Apache 41773, Log4Shell) + LDAP anon bind come from docker-compose.yml.
#
# Runs on ANY mainstream Linux — it detects the package manager (apt/dnf/yum/
# pacman/zypper/apk) and the init system (systemd / OpenRC / SysV) and adapts.
#
# Usage:  sudo ./setup_target.sh            # set up
#         sudo ./setup_target.sh --teardown # remove the lab services/user
set -euo pipefail

LAB_USER="${LAB_USER:-labadmin}"
LAB_PASS="${LAB_PASS:-Passw0rd!}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }; }
log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# ---- package manager / init abstraction (so this runs on "any linux") -------
PM=""
detect_pm() {
  for c in apt-get dnf yum pacman zypper apk; do
    if command -v "$c" >/dev/null 2>&1; then PM="$c"; return; fi
  done
  warn "No supported package manager found (apt/dnf/yum/pacman/zypper/apk)."
  warn "Install openssh-server, vsftpd and net-snmp manually, then re-run."
  exit 1
}

pm_install() {
  # $@ = logical packages; map the ones whose names differ per distro.
  export DEBIAN_FRONTEND=noninteractive
  case "$PM" in
    apt-get) apt-get update -y -q && apt-get install -y -q "$@" ;;
    dnf)     dnf install -y "$@" ;;
    yum)     yum install -y "$@" ;;
    pacman)  pacman -Sy --noconfirm "$@" ;;
    zypper)  zypper --non-interactive install "$@" ;;
    apk)     apk add --no-cache "$@" ;;
  esac
}

# Logical package -> per-PM names. Prints the right names for the current PM.
pkgs_for() {
  case "$PM" in
    apt-get) echo "openssh-server vsftpd snmpd snmp" ;;
    dnf|yum) echo "openssh-server vsftpd net-snmp net-snmp-utils" ;;
    pacman)  echo "openssh vsftpd net-snmp" ;;
    zypper)  echo "openssh vsftpd net-snmp" ;;
    apk)     echo "openssh vsftpd net-snmp" ;;
  esac
}

# svc <action> <name...> — try systemd, then OpenRC (Alpine), then SysV. The
# ssh unit is 'ssh' on Debian but 'sshd' elsewhere, so callers pass both names.
svc() {
  local action="$1"; shift
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    # 'disable' should also stop the running service; '--now' does both.
    [ "$action" = disable ] && action="disable --now"
    # shellcheck disable=SC2086
    for n in "$@"; do systemctl $action "$n" 2>/dev/null && return 0 || true; done
  elif command -v rc-service >/dev/null 2>&1; then          # OpenRC (Alpine)
    for n in "$@"; do
      case "$action" in
        enable)  rc-update add "$n" default 2>/dev/null && rc-service "$n" start 2>/dev/null && return 0 || true ;;
        disable) rc-service "$n" stop 2>/dev/null; rc-update del "$n" default 2>/dev/null; return 0 ;;
        *)       rc-service "$n" "$action" 2>/dev/null && return 0 || true ;;
      esac
    done
  elif command -v service >/dev/null 2>&1; then             # SysV
    for n in "$@"; do service "$n" "${action/enable/start}" 2>/dev/null && return 0 || true; done
  fi
  warn "could not $action service ($*) — start it manually for the lab to work."
  return 0
}

teardown() {
  need_root
  warn "Tearing down lab services..."
  svc disable vsftpd
  svc disable snmpd
  if id "$LAB_USER" >/dev/null 2>&1; then userdel -r "$LAB_USER" 2>/dev/null || true; fi
  log "Done. (Docker services: 'cd deploy && docker compose down -v')"
}

setup() {
  need_root
  detect_pm
  cat <<'BANNER'
==========================================================================
  ⚠  Configuring INTENTIONALLY VULNERABLE services (LAB ONLY).
     Isolate this host. Do not expose to the internet unfirewalled.
==========================================================================
BANNER
  log "Package manager: $PM. Installing $(pkgs_for)..."
  # shellcheck disable=SC2046
  pm_install $(pkgs_for)

  # --- SSH lab user (weak password) -------------------------------------
  log "Creating SSH lab user '$LAB_USER' with a weak password..."
  if ! id "$LAB_USER" >/dev/null 2>&1; then useradd -m -s /bin/bash "$LAB_USER"; fi
  echo "${LAB_USER}:${LAB_PASS}" | chpasswd
  # allow password auth (brute-force target)
  if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
  fi
  # host keys may be absent on a fresh openssh (Arch/Alpine) — generate them.
  command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -A >/dev/null 2>&1 || true
  svc enable ssh sshd
  svc restart ssh sshd

  # --- FTP anonymous ----------------------------------------------------
  log "Enabling anonymous FTP (vsftpd)..."
  # config path differs: /etc/vsftpd.conf (Debian) vs /etc/vsftpd/vsftpd.conf (RHEL/Arch).
  VSFTPD_CONF=/etc/vsftpd.conf
  [ -d /etc/vsftpd ] && VSFTPD_CONF=/etc/vsftpd/vsftpd.conf
  cat >"$VSFTPD_CONF" <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=NO
anon_root=/srv/ftp
no_anon_password=YES
seccomp_sandbox=NO
EOF
  # vsftpd refuses to start if the anon root is writable; keep it tidy + present.
  mkdir -p /srv/ftp && chmod 755 /srv/ftp
  echo "MyGovNet BAS lab — anonymous FTP" >/srv/ftp/README.txt
  svc enable vsftpd
  svc restart vsftpd

  # --- SNMP public community -------------------------------------------
  log "Enabling SNMP with 'public' community..."
  mkdir -p /etc/snmp
  cat >/etc/snmp/snmpd.conf <<'EOF'
agentaddress udp:161
rocommunity public default
sysLocation MyGovNet BAS Lab
sysContact lab@example.local
EOF
  svc enable snmpd
  svc restart snmpd

  # --- make the attacker side work out of the box (2-in-1) --------------
  # ssh_brute tests ONE known credential from HARNESS_DC_USER/PASS (not a
  # wordlist). Drop a git-ignored credentials.env pointing at the lab user so
  # the self-test shows ssh_brute SUCCESS without the operator exporting vars.
  # (Never overwrite an existing one — it may hold your AD DC creds.)
  CRED_FILE="$REPO_DIR/credentials.env"
  if [ ! -f "$CRED_FILE" ]; then
    cat >"$CRED_FILE" <<EOF
# Auto-written by deploy/setup_target.sh for the LINUX lab target (git-ignored).
# ssh_brute uses these as its single known credential. For a Windows AD DC,
# set HARNESS_DC_USER=Administrator and the DC password instead.
HARNESS_DC_USER=${LAB_USER}
HARNESS_DC_PASS=${LAB_PASS}
EOF
    chmod 600 "$CRED_FILE"
    log "Wrote $CRED_FILE (ssh_brute will use ${LAB_USER}/${LAB_PASS})."
  else
    warn "credentials.env already exists — leaving it. For ssh_brute to hit this box: export HARNESS_DC_USER=${LAB_USER} HARNESS_DC_PASS='${LAB_PASS}'"
  fi

  cat <<EOF

$(log "Host services ready.")
  SSH   : ${LAB_USER} / ${LAB_PASS}   @ :22
  FTP   : anonymous @ :21
  SNMP  : community 'public' @ udp/161

Next — web CVEs + LDAP:  cd deploy && docker compose up -d
Verify:                  python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe

Note: on SELinux/firewalld distros (RHEL/Fedora), you may need to open ports
(firewall-cmd) and allow FTP (setsebool -P ftpd_anon_write / ftpd_full_access)
for remote tests; localhost self-tests work as-is.
EOF
}

case "${1:-setup}" in
  --teardown|-d|teardown) teardown ;;
  *) setup ;;
esac
