#!/usr/bin/env bash
# add-ssh-port.sh — make the Debian lab host's sshd ALSO listen on an extra TCP
# port (default 8181), keeping the existing port(s). Run AS ROOT on the droplet.
#
#   ssh -p 2222 labadmin@<droplet>      # get onto the Debian host
#   sudo bash add-ssh-port.sh 8181      # add 8181 (or any port)
#
# Why 8181: it's in the SD-WAN's allowed-port policy (Polisi Standard Security
# v1.3), so an SSH listener there passes the boundary when 2222 is filtered.
#
# Safe: validates the config with `sshd -t` BEFORE applying, RELOADs (doesn't
# drop your current session), is idempotent, and opens the host firewall. It does
# NOT touch your DNAT forwarding (/root/startup.sh) — sshd binds the port directly.
set -euo pipefail

PORT="${1:-8181}"
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "[!] usage: sudo bash add-ssh-port.sh <port>   (1-65535; default 8181)" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] must run as root (sudo bash add-ssh-port.sh $PORT)" >&2
    exit 1
fi

DROPIN="/etc/ssh/sshd_config.d/zz-extra-port-${PORT}.conf"
mkdir -p /etc/ssh/sshd_config.d

# Some older sshd builds don't read sshd_config.d — make sure the Include is there.
if ! grep -qsE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    echo "[i] added the sshd_config.d Include to /etc/ssh/sshd_config"
fi

if [ -f "$DROPIN" ] && grep -qsE "^\s*Port\s+${PORT}\b" "$DROPIN"; then
    echo "[i] sshd already configured for Port ${PORT} ($DROPIN) — re-validating."
else
    printf 'Port %s\n' "$PORT" > "$DROPIN"
    echo "[+] wrote $DROPIN (Port ${PORT})"
fi

# Validate BEFORE applying so a bad config can't lock you out.
if ! sshd -t; then
    echo "[!] sshd -t FAILED — removing the drop-in and aborting (ssh unchanged)." >&2
    rm -f "$DROPIN"
    exit 1
fi
echo "[ok] sshd config valid."

# Open the host firewall (whichever is active).
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qi active; then
    ufw allow "${PORT}/tcp" >/dev/null && echo "[+] ufw allow ${PORT}/tcp"
else
    if ! iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT && echo "[+] iptables: accept tcp/${PORT}"
    fi
    command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 \
        && echo "[+] iptables rule persisted (netfilter-persistent)" || true
fi

# Apply WITHOUT dropping the current session.
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
    || systemctl restart ssh 2>/dev/null || systemctl restart sshd
echo "[ok] sshd reloaded — now listening on ${PORT} (and its existing ports)."

echo
echo "Verify from your tester box:"
echo "   ssh -p ${PORT} labadmin@<droplet-ip>"
echo "   (or:  nc -vz <droplet-ip> ${PORT} )"
echo
echo "NOTE: if a DigitalOcean CLOUD firewall is attached to the droplet, also add"
echo "an inbound rule for TCP ${PORT} in the DO console — this script can't change"
echo "that. The SD-WAN already permits ${PORT} if it's in the Polisi allow-list."
