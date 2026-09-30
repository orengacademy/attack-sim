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
    c("\nDone. hping3 and responder both need root at run time:", "1;32")
    print("  - hping3 (ICMP Flood): grant it once with")
    print("      sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)")
    print("  - responder (PetitPotam): run the harness itself with sudo")
    c("\nNow run:  python3 gui.py  (or: sudo python3 gui.py for PetitPotam)", "1;32")


if __name__ == "__main__":
    main()
