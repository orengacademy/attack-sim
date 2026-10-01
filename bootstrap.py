#!/usr/bin/env python3
"""
bootstrap.py — one-shot setup for the harness on Kali/Debian.

Installs the APT packages the attack modules need. By default it installs the
CORE set (what the non-active modules use). Pass --with-active to also install the
active-establishment tooling that the live USS modules shell out to under --active
(and print hints for the few tools that have no distro package).

    python3 bootstrap.py                 # core tooling
    python3 bootstrap.py --with-active    # + active-establishment tunnels/exec
"""

import os
import shutil
import subprocess
import sys

# What the default (indicator / non-active) modules use.
CORE_APT = [
    "python3-tk", "curl", "snmp", "hydra", "impacket-scripts",
    "ldap-utils", "hping3", "responder",
    "dnsutils",          # dig — covert_channel / DNS checks
    "openssh-client",    # ssh — ssh_over_443 (--active) and general use
]

# Extra APT tools used only by active-establishment modules (--active). Installed
# individually (tolerant) because availability varies by distro/repo.
ACTIVE_APT = [
    "iodine",            # dns_tunnel (--active)
    "evil-winrm",        # eastwest_lateral WinRM exec (--active)
    "ptunnel-ng",        # icmp_exfil (--active); falls back to 'ptunnel'
]

# Active tools with NO reliable distro package — installed out-of-band.
ACTIVE_MANUAL = {
    "chisel":  "github.com/jpillora/chisel/releases (Go binary) — self_tunnel_vps / socks_pivot",
    "gost":    "github.com/go-gost/gost/releases (Go binary) — self_tunnel_vps / socks_pivot",
    "wstunnel": "github.com/erebe/wstunnel/releases (Go binary) — self_tunnel_vps",
    "dnscat2": "github.com/iagox86/dnscat2 (clone + make) — dns_tunnel alternative",
}


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


def install_core():
    c("Checking CORE APT packages...")
    missing = [p for p in CORE_APT if not apt_installed(p)]
    if not missing:
        print("  all core APT packages already installed.")
        return
    print("  missing:", ", ".join(missing))
    run(sudo(["apt-get", "update"]))
    run(sudo(["apt-get", "install", "-y"] + missing))


def install_active():
    c("\nInstalling ACTIVE-establishment tooling (--with-active)...", "1;33")
    run(sudo(["apt-get", "update"]))
    for pkg in ACTIVE_APT:
        if apt_installed(pkg):
            print(f"  {pkg}: already installed")
            continue
        print(f"  installing {pkg}…")
        r = run(sudo(["apt-get", "install", "-y", pkg]))
        if r.returncode != 0 and pkg == "ptunnel-ng":
            run(sudo(["apt-get", "install", "-y", "ptunnel"]))   # older name
        if r.returncode != 0:
            print(f"  [!] {pkg} not available via apt — install manually if you need it.")
    c("\n  Active tools with no distro package (install if you need that module):", "1;33")
    for tool, where in ACTIVE_MANUAL.items():
        have = "present" if shutil.which(tool) else "MISSING"
        print(f"   - {tool:<9} [{have}] — {where}")


def main():
    with_active = "--with-active" in sys.argv[1:]
    c("=== Harness bootstrap ===", "1;32")
    install_core()
    if with_active:
        install_active()
    else:
        print("\n(active-establishment tools NOT installed — re-run with --with-active "
              "if you'll use --active)")
    c("\nDone. Run the harness as your NORMAL user (do NOT use sudo python3 gui.py —", "1;32")
    print("  that makes sudo prompt for 'python3'). The root-needing modules")
    print("  (ICMP/SYN flood, PetitPotam, stateful_evasion) self-elevate via `sudo -n`.")
    print("  Enable that without prompts via ONE of:")
    print("   - setcap (hping3 floods): sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)")
    print("   - NOPASSWD sudoers:       <user> ALL=(root) NOPASSWD: $(command -v hping3), $(command -v responder)")
    c("\nCredentials: set HARNESS_DC_PASS (and HARNESS_DOMAIN/HARNESS_DC_USER),", "1;32")
    print("  or copy credentials.env.example -> credentials.env and fill it in.")
    c("USS infra: copy config.json.example -> config.json for your VPS/domain/canary;", "1;32")
    print("  detections.json for the DETECTED verdict. Check readiness: python3 preflight.py")
    c("\nNow run:  python3 gui.py   (or: python3 cli.py --list)", "1;32")


if __name__ == "__main__":
    main()
