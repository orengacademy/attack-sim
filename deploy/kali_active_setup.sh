#!/usr/bin/env bash
# =============================================================================
#  kali_active_setup.sh  —  one-shot "plug & play" runner for the attack-sim
#  harness from a tester host (Kali), with FULL --active egress/C2/exfil infra.
#
#  SANITIZED TEMPLATE. No secrets are committed — fill the <<...>> placeholders
#  below (or pass them as env vars), save your filled copy OUTSIDE git (it is
#  git-ignored as config.json / credentials.env anyway), and run:
#
#      sudo bash deploy/kali_active_setup.sh
#
#  It:
#    1. SELF-ELEVATES to root (needs root for raw-socket / DoS / responder
#       modules). One sudo prompt up front — no mid-run prompts.
#    2. Writes a prefilled config.json + credentials.env (both git-ignored).
#    3. Exports the DC creds into the ENV so impacket/noPac never block on a
#       getpass() "Password:" prompt, and runs the harness with stdin disabled.
#    4. Installs the client tools (sshpass, chisel, + optional hping3/responder/
#       snmp that unlock PREREQ-MISSING modules).
#    5. Runs the full --active battery, then an ssh_over_443 pass, flipping the
#       attacker VPS between its chisel server and sshd-on-443 (see VPS SETUP).
#
#  -----------------------------------------------------------------------------
#  VPS SETUP (do this once on a SEPARATE box you control — NOT the target):
#    scp deploy/attacker_endpoint.py root@<vps>:/root/
#    # run the HTTP/TCP/UDP sink (logging) as a service, OR for the tunnel tests:
#    #   - chisel server --port 443 --socks5 --reverse        (self_tunnel/socks)
#    #   - a /root/use443.sh toggle that swaps :443 chisel <-> sshd for ssh_over_443
#    # (ssh_over_443 and chisel cannot share :443 — the toggle flips between them)
#  The attacker VPS must be a DIFFERENT host from the target: an egress test to
#  the box you are attacking is meaningless.
#  -----------------------------------------------------------------------------
#  NOTE: these egress/C2 modules test the TESTER host's egress path. Run from
#  BEHIND the SD-WAN for a real control verdict; direct-to-internet only proves
#  the tester's own egress is open.  Authorised-engagement use only.
# =============================================================================
set +e

# ---- FILL THESE (or export them before running) -----------------------------
REPO="${REPO:-<<PATH_TO_attack-sim_REPO>>}"        # e.g. /home/kali/Projects/attack-sim
TGT="${TGT:-<<TARGET_IP>>}"                        # the vuln target to test
VPS="${VPS:-<<ATTACKER_VPS_IP>>}"                  # your attacker box (NOT the target)
VPS_PASS="${VPS_PASS:-<<VPS_SSH_PASSWORD>>}"       # or set up key auth and drop sshpass

# attacker infra for config.json
CANARY_URL="${CANARY_URL:-<<WEBHOOK_OR_CANARY_HTTPS_URL>>}"     # e.g. https://webhook.site/<uuid>
CANARY_DNS="${CANARY_DNS:-<<CANARYTOKEN_DNS_HOSTNAME>>}"        # e.g. abc123.canarytokens.com
PIVOT="${PIVOT:-<<PIVOT_HOST:PORT>>}"              # a host:port reachable FROM the VPS (socks_pivot)

# lab DC / SSH creds for credentials.env
DOMAIN="${DOMAIN:-<<AD_DOMAIN>>}"                  # e.g. lab.local
DC_USER="${DC_USER:-<<DC_USER>>}"                  # e.g. Administrator
DC_PASS="${DC_PASS:-<<DC_PASSWORD>>}"
SSH_USER="${SSH_USER:-$DC_USER}"                   # ssh_brute creds (falls back to DC creds)
SSH_PASS="${SSH_PASS:-$DC_PASS}"
# -----------------------------------------------------------------------------

# 1) require root — self-elevate so there are no mid-run sudo prompts and the
#    raw-socket / DoS / responder modules have the privilege they need.
if [ "$EUID" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

case "$REPO$TGT$VPS" in *"<<"*) echo "[!] Fill the <<...>> placeholders (or export them) first."; exit 2;; esac
OWNER="${SUDO_USER:-$(id -un)}"
cd "$REPO" || { echo "[!] repo not found: $REPO (set REPO=...)"; exit 1; }

# 2) creds in the ENV too, so noPac/psexec/ssh_brute never block on getpass("Password:")
export HARNESS_DOMAIN="$DOMAIN" HARNESS_DC_USER="$DC_USER" HARNESS_DC_PASS="$DC_PASS" \
       HARNESS_SSH_USER="$SSH_USER" HARNESS_SSH_PASS="$SSH_PASS"

# credentials.env (0600, owned by the invoking user; git-ignored)
cat > credentials.env <<CRED
HARNESS_DOMAIN=$DOMAIN
HARNESS_DC_USER=$DC_USER
HARNESS_DC_PASS=$DC_PASS
HARNESS_SSH_USER=$SSH_USER
HARNESS_SSH_PASS=$SSH_PASS
CRED
chmod 600 credentials.env; chown "$OWNER":"$OWNER" credentials.env 2>/dev/null

# config.json (attacker infra; git-ignored)
cat > config.json <<CFG
{
  "canary_url": "$CANARY_URL",
  "attacker_domain": "$CANARY_DNS",
  "canary_dns_zone": "$CANARY_DNS",
  "attacker_vps": "$VPS",
  "internal_pivot_target": "$PIVOT",
  "attacker_doh": "", "front_domain": "", "front_host": "", "published_app_url": "",
  "lots_saas": [], "switch_targets": [], "ipv6_target": "",
  "external_resolver": "8.8.8.8",
  "doh_providers": ["https://cloudflare-dns.com/dns-query","https://dns.google/resolve","https://dns.quad9.net:5053/dns-query"],
  "beacon_seconds": 60, "beacon_interval": 5
}
CFG
chown "$OWNER":"$OWNER" config.json 2>/dev/null
echo "[+] wrote config.json + credentials.env (git-ignored)"

# 3) client tools
command -v sshpass >/dev/null || apt-get install -y sshpass
command -v chisel  >/dev/null || apt-get install -y chisel 2>/dev/null || {
  curl -sSL -o /tmp/chisel.gz https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
  gunzip -f /tmp/chisel.gz && install -m755 /tmp/chisel /usr/local/bin/chisel; }
apt-get install -y hping3 responder snmp >/dev/null 2>&1   # unlock PREREQ-MISSING modules

SSHV="sshpass -p $VPS_PASS ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# 4) full --active battery (VPS :443 = chisel). </dev/null => nothing can hang on a prompt.
$SSHV "root@$VPS" '/root/use443.sh chisel' >/dev/null 2>&1
python3 cli.py --target "$TGT" --all --active --confirm-roe </dev/null

# 5) ssh_over_443 pass (flip VPS :443 -> sshd, then back to chisel)
$SSHV "root@$VPS" '/root/use443.sh ssh' >/dev/null 2>&1; sleep 2
python3 cli.py --target "$TGT" --only ssh_over_443 --active --confirm-roe </dev/null
$SSHV "root@$VPS" '/root/use443.sh chisel' >/dev/null 2>&1

echo "[+] done — evidence in ./evidence/ ; check your canary + Canarytokens dashboards"
