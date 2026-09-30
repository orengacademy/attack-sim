#!/usr/bin/env python3
"""
bootstrap.py — one-shot setup for the harness on Kali.

Auto-checks and installs the APT packages the 12 attack modules need
(curl, snmp, hydra, impacket-scripts, ldap-utils, hping3, responder,
python3-tk). No config file, no PIP packages, no daemon to start.

Run once (uses sudo for apt):
    python3 bootstrap.py
"""

import os
import subprocess

APT_PACKAGES = [
    "python3-tk", "curl", "snmp", "hydra", "impacket-scripts",
    "ldap-utils", "hping3", "responder",
]


def c(msg, code="1;36"):
    print(f"\033[{code}m{msg}\033[0m")


def run(cmd, check=False):
    print("  $", " ".join(cmd))
    return subprocess.run(cmd, check=check)


def sudo(cmd):
    return cmd if os.geteuid() == 0 else ["sudo"] + cmd


def apt_installed(pkg):
    r = subprocess.run(["dpkg", "-s", pkg], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    return r.returncode == 0


def install_apt():
    c("Checking APT packages...")
    missing = [p for p in APT_PACKAGES if not apt_installed(p)]
    if not missing:
        print("  all APT packages already installed.")
        return
    print("  missing:", ", ".join(missing))
    run(sudo(["apt-get", "update"]))
    run(sudo(["apt-get", "install", "-y"] + missing))


def main():
    c("=== Harness bootstrap ===", "1;32")
    install_apt()
    c("\nDone. Run the harness as your NORMAL user (do NOT use sudo python3 gui.py —", "1;32")
    print("  that makes sudo prompt for 'python3'). The root-needing modules")
    print("  (ICMP/SYN flood, PetitPotam) self-elevate their tool via `sudo -n`.")
    print("  Enable that without prompts via ONE of:")
    print("   - setcap (hping3 floods): sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)")
    print("   - NOPASSWD sudoers:       <user> ALL=(root) NOPASSWD: $(command -v hping3), $(command -v responder)")
    c("\nCredentials: set HARNESS_DC_PASS (and HARNESS_DOMAIN/HARNESS_DC_USER),", "1;32")
    print("  or copy credentials.env.example -> credentials.env and fill it in.")
    print("  Check readiness first:  python3 preflight.py")
    c("\nNow run:  python3 gui.py", "1;32")


if __name__ == "__main__":
    main()
