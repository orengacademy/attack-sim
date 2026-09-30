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
# Usage:  sudo ./setup_target.sh            # set up
#         sudo ./setup_target.sh --teardown # remove the lab services/user
set -euo pipefail

LAB_USER="${LAB_USER:-labadmin}"
LAB_PASS="${LAB_PASS:-Passw0rd!}"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }; }
log() { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

teardown() {
  need_root
  warn "Tearing down lab services..."
  systemctl disable --now vsftpd 2>/dev/null || true
  systemctl disable --now snmpd 2>/dev/null || true
  if id "$LAB_USER" >/dev/null 2>&1; then userdel -r "$LAB_USER" 2>/dev/null || true; fi
  log "Done. (Docker services: 'cd deploy && docker compose down -v')"
}

setup() {
  need_root
  cat <<'BANNER'
==========================================================================
  ⚠  Configuring INTENTIONALLY VULNERABLE services (LAB ONLY).
     Isolate this host. Do not expose to the internet unfirewalled.
==========================================================================
BANNER
  export DEBIAN_FRONTEND=noninteractive
  log "Installing packages (openssh-server vsftpd snmpd)..."
  apt-get update -y -q
  apt-get install -y -q openssh-server vsftpd snmpd snmp

  # --- SSH lab user (weak password) -------------------------------------
  log "Creating SSH lab user '$LAB_USER' with a weak password..."
  if ! id "$LAB_USER" >/dev/null 2>&1; then useradd -m -s /bin/bash "$LAB_USER"; fi
  echo "${LAB_USER}:${LAB_PASS}" | chpasswd
  # allow password auth (brute-force target)
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

  # --- FTP anonymous ----------------------------------------------------
  log "Enabling anonymous FTP (vsftpd)..."
  cat >/etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=NO
anon_root=/srv/ftp
no_anon_password=YES
EOF
  mkdir -p /srv/ftp && echo "MyGovNet BAS lab — anonymous FTP" >/srv/ftp/README.txt
  systemctl enable --now vsftpd

  # --- SNMP public community -------------------------------------------
  log "Enabling SNMP with 'public' community..."
  cat >/etc/snmp/snmpd.conf <<'EOF'
agentaddress udp:161
rocommunity public default
sysLocation MyGovNet BAS Lab
sysContact lab@example.local
EOF
  systemctl enable --now snmpd

  cat <<EOF

$(log "Host services ready.")
  SSH   : ${LAB_USER} / ${LAB_PASS}   (set: export HARNESS_DC_USER=${LAB_USER} HARNESS_DC_PASS='${LAB_PASS}')
  FTP   : anonymous @ :21
  SNMP  : community 'public' @ udp/161

Next — web CVEs + LDAP:  cd deploy && docker compose up -d
Verify:                  python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe
EOF
}

case "${1:-setup}" in
  --teardown|-d|teardown) teardown ;;
  *) setup ;;
esac
