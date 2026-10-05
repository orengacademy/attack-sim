#!/usr/bin/env bash
# grant-ssh-access.sh — set up SSH access to the Debian lab host the way the
# operator asked: log in as root OR a named user, over port 2222 AND an extra
# port (default 8181). Run AS ROOT on the droplet.
#
#   # password is read from $NEWPASS (not argv) so it doesn't land in shell history:
#   sudo NEWPASS='YourStrongPass' bash grant-ssh-access.sh            # user=oreng, port 8181, root login on
#   sudo NEWPASS='...' SSH_USER=oreng EXTRA_PORT=8181 PERMIT_ROOT=yes bash grant-ssh-access.sh
#
# What it does (idempotent, validates before applying, reloads without dropping
# your session):
#   * creates/updates $SSH_USER with a password and sudo
#   * sets root's password to the same (so `ssh root@host` works) when PERMIT_ROOT=yes
#   * enables password login + (optionally) root login in sshd
#   * makes sshd ALSO listen on $EXTRA_PORT (keeps 2222)
#   * opens the host firewall for $EXTRA_PORT
#
# SECURITY: enabling root-with-password SSH is a downgrade. Prefer PERMIT_ROOT=no
# and use `oreng` + sudo, and/or switch to SSH keys once you're in. This is a
# throwaway lab, so the operator's call.
set -euo pipefail

SSH_USER="${SSH_USER:-oreng}"
EXTRA_PORT="${EXTRA_PORT:-8181}"
PERMIT_ROOT="${PERMIT_ROOT:-yes}"
NEWPASS="${NEWPASS:-}"

if [ "$(id -u)" -ne 0 ]; then echo "[!] run as root" >&2; exit 1; fi
if [ -z "$NEWPASS" ]; then
    echo "[!] set the password in \$NEWPASS, e.g.:  sudo NEWPASS='Str0ngPass' bash $0" >&2
    exit 2
fi
if ! [[ "$EXTRA_PORT" =~ ^[0-9]+$ ]] || [ "$EXTRA_PORT" -lt 1 ] || [ "$EXTRA_PORT" -gt 65535 ]; then
    echo "[!] EXTRA_PORT must be 1-65535" >&2; exit 2
fi

# ---- 1) user + sudo ------------------------------------------------------
if id "$SSH_USER" >/dev/null 2>&1; then
    echo "[i] user $SSH_USER exists"
else
    useradd -m -s /bin/bash "$SSH_USER"
    echo "[+] created user $SSH_USER"
fi
printf '%s:%s\n' "$SSH_USER" "$NEWPASS" | chpasswd
usermod -aG sudo "$SSH_USER" 2>/dev/null || usermod -aG wheel "$SSH_USER" 2>/dev/null || true
echo "[+] $SSH_USER password set + added to sudo"

if [ "$PERMIT_ROOT" = "yes" ]; then
    printf 'root:%s\n' "$NEWPASS" | chpasswd
    echo "[+] root password set (PERMIT_ROOT=yes)"
fi

# ---- 2) sshd: password auth, extra port, (optional) root login ----------
mkdir -p /etc/ssh/sshd_config.d
if ! grep -qsE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi
DROPIN="/etc/ssh/sshd_config.d/zz-lab-access.conf"
{
    echo "# managed by grant-ssh-access.sh"
    echo "Port 2222"
    echo "Port ${EXTRA_PORT}"
    echo "PasswordAuthentication yes"
    [ "$PERMIT_ROOT" = "yes" ] && echo "PermitRootLogin yes" || echo "PermitRootLogin prohibit-password"
} > "$DROPIN"
echo "[+] wrote $DROPIN"

# Validate BEFORE applying so a typo can't lock everyone out.
if ! sshd -t; then
    echo "[!] sshd -t FAILED — reverting the drop-in, ssh unchanged." >&2
    rm -f "$DROPIN"; exit 1
fi
echo "[ok] sshd config valid"

# ---- 3) firewall for the extra port -------------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qi active; then
    ufw allow 2222/tcp >/dev/null 2>&1 || true
    ufw allow "${EXTRA_PORT}/tcp" >/dev/null && echo "[+] ufw allow ${EXTRA_PORT}/tcp"
else
    for p in 2222 "$EXTRA_PORT"; do
        iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
    done
    command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
    echo "[+] iptables: accept tcp/2222 + tcp/${EXTRA_PORT}"
fi

# ---- 4) apply without dropping the current session ----------------------
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
    || systemctl restart ssh 2>/dev/null || systemctl restart sshd
echo "[ok] sshd reloaded — listening on 2222 + ${EXTRA_PORT}"

echo
echo "Test from your tester box:"
echo "   ssh -p 2222 ${SSH_USER}@<droplet>"
echo "   ssh -p ${EXTRA_PORT} ${SSH_USER}@<droplet>"
[ "$PERMIT_ROOT" = "yes" ] && echo "   ssh -p ${EXTRA_PORT} root@<droplet>"
echo
echo "If a DigitalOcean CLOUD firewall is attached, also add an inbound TCP"
echo "${EXTRA_PORT} rule in the DO console (this script can't change that)."
