#!/usr/bin/env bash
# refresh-lab.sh — keep the deliberately-vulnerable lab UP and healthy. Idempotent;
# safe to run every few minutes from cron. It does NOT reconfigure anything (that's
# setup_target.sh / setup_all.sh) — it only (re)starts whatever has died:
#   - host services: ssh / vsftpd / snmpd
#   - docker web/dir containers (compose up -d brings back any exited ones)
#   - the libvirt Windows AD DC VM (started if it's shut off)
#
# Install the 5-minute cron (run once, as root):
#   sudo deploy/refresh-lab.sh --install-cron
# Remove it:
#   sudo deploy/refresh-lab.sh --remove-cron
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRON="/etc/cron.d/mygovnet-lab"
LOG="/var/log/mygovnet-refresh.log"
WIN_VM="${WIN_VM:-win2019}"

# Health probe: a container can be "up" yet not SERVING (the app crashed inside,
# e.g. an OOM/crash-loop). `compose up -d` won't fix that — it's already "up". So
# after the normal refresh, probe the expected web/dir ports and force-recreate
# the containers if any that should be listening are dead. Configurable /
# disable-able via HARNESS_HEALTH_PORTS (space-separated; empty = skip).
HEALTH_PORTS="${HARNESS_HEALTH_PORTS-80 8080 389}"

port_down() {  # 0 (true) if nothing is listening on 127.0.0.1:$1
    timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$1" 2>/dev/null && return 1 || return 0
}

health_recreate() {
    command -v docker >/dev/null 2>&1 || return 0
    [ -n "${HEALTH_PORTS// /}" ] || return 0
    local down=""
    for p in $HEALTH_PORTS; do port_down "$p" && down="$down $p"; done
    [ -n "$down" ] || return 0
    # up-but-not-serving -> recreate the containers so the crashed app comes back
    ( cd "$HERE" && { docker compose up -d --force-recreate >/dev/null 2>&1 \
        || docker-compose up -d --force-recreate >/dev/null 2>&1; } ) || true
    HEALTH_NOTE=" + health-recreated (ports down:$down)"
}

svc_up() {
    # start a service only if it exists and isn't already active (no-op otherwise)
    for n in "$@"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^$n"; then
            systemctl is-active --quiet "$n" || systemctl start "$n" 2>/dev/null || true
            return 0
        fi
    done
}

install_cron() {
    [ "$(id -u)" -eq 0 ] || { echo "run as root to install the cron"; exit 1; }
    cat >"$CRON" <<EOF
# MyGovNet vuln-lab keep-alive — re-starts any dead service/container every 5 min.
*/5 * * * * root $HERE/refresh-lab.sh >>$LOG 2>&1
EOF
    chmod 644 "$CRON"
    echo "[*] installed $CRON (every 5 min; log: $LOG)"
    echo "    first run now:"; "$HERE/refresh-lab.sh"
}

remove_cron() {
    [ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
    rm -f "$CRON" && echo "[*] removed $CRON"
}

refresh() {
    ts="$(date '+%F %T')"
    # 1) host services
    svc_up ssh sshd
    svc_up vsftpd
    svc_up snmpd
    # 2) docker web/dir containers — recreate any that exited
    if command -v docker >/dev/null 2>&1; then
        if docker compose version >/dev/null 2>&1; then
            ( cd "$HERE" && docker compose up -d >/dev/null 2>&1 ) || true
        elif command -v docker-compose >/dev/null 2>&1; then
            ( cd "$HERE" && docker-compose up -d >/dev/null 2>&1 ) || true
        fi
    fi
    # 2b) health probe — recreate any container that's up but not serving
    HEALTH_NOTE=""
    health_recreate
    # 3) libvirt Windows DC — start it if it's shut off (never force-reboot a live one)
    if command -v virsh >/dev/null 2>&1; then
        state="$(virsh -c qemu:///system domstate "$WIN_VM" 2>/dev/null || true)"
        [ "$state" = "shut off" ] && virsh -c qemu:///system start "$WIN_VM" >/dev/null 2>&1 || true
    fi
    echo "$ts refreshed (host svc + containers${state:+ + win=$state})${HEALTH_NOTE}"
}

case "${1:-refresh}" in
    --install-cron) install_cron ;;
    --remove-cron)  remove_cron ;;
    *)              refresh ;;
esac
