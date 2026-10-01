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


def _which_missing(pkgs):
    """apt reports its own exit code, but that only tells us the *install
    command* didn't error — not that the binaries are actually usable
    afterwards (e.g. install succeeded but PATH/shell differs). Re-check with
    the same apt_installed() probe used before install, so a failure here is
    never silently swallowed."""
    return [p for p in pkgs if not apt_installed(p)]


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
        return []
    print("  missing:", ", ".join(missing))
    r_update = run(sudo(["apt-get", "update"]))
    if r_update.returncode != 0:
        c(f"  [!] 'apt-get update' failed (exit {r_update.returncode}) — installs below "
          f"may use a stale/broken package list.", "1;31")
    r_install = run(sudo(["apt-get", "install", "-y"] + missing))
    if r_install.returncode != 0:
        c(f"  [!] 'apt-get install' exited {r_install.returncode} — see the apt output above "
          f"for the real reason (no internet, broken repo, GPG error, etc).", "1;31")
    still_missing = _which_missing(missing)
    if still_missing:
        c(f"  [!] still missing after install attempt: {', '.join(still_missing)}", "1;31")
    return still_missing


def ensure_impacket_module():
    """The AD modules (wmiexec/nopac/dcsync/…) import the `impacket` PYTHON
    module, not just the CLI wrappers in impacket-scripts. On Kali the apt
    package pulls python3-impacket, but elsewhere it may be absent — in which
    case loader.py silently skips wmiexec.py ("No module named 'impacket'").
    Verify it imports; if not, install python3-impacket (apt) or pip it."""
    try:
        import impacket  # noqa: F401
        print("  impacket python module: present")
        return
    except ImportError:
        pass
    c("  impacket python module MISSING — installing (needed by wmiexec/nopac/dcsync)…", "1;33")
    if not apt_installed("python3-impacket"):
        run(sudo(["apt-get", "install", "-y", "python3-impacket"]))
    try:
        import impacket  # noqa: F401
        return
    except ImportError:
        pass
    # no distro package — pip into the user env (PEP 668: allow break-system-packages)
    r = run([sys.executable, "-m", "pip", "install", "--user", "impacket"])
    if r.returncode != 0:
        run([sys.executable, "-m", "pip", "install", "--user",
             "--break-system-packages", "impacket"])
    try:
        import impacket  # noqa: F401
        print("  impacket python module: installed")
    except ImportError:
        print("  [!] impacket still not importable — install it manually "
              "(pip install impacket); wmiexec/nopac/dcsync will stay skipped.")


def ensure_impacket_runtime():
    """Exercise the ACTUAL runtime import chain the in-process AD modules use —
    which `import impacket` alone does NOT. The real noPac/sAMAccountName breakage
    is ldapdomaindump -> dns.resolver -> dns.asyncquery -> cryptography.hazmat.asn1,
    tripped by a stale USER-SITE cryptography shadowing a newer system one. Import
    those leaves and, on failure, point at the fix. Skips cleanly if a lib is
    simply not installed on this box (ensure_impacket_module covers impacket)."""
    import importlib
    err = failed = None
    for mod in ("impacket.examples.secretsdump", "ldapdomaindump", "dns.asyncquery"):
        try:
            importlib.import_module(mod)
        except ImportError as ex:
            # a genuinely-absent lib is not the shadow bug — leave it to apt/pip
            if "asn1" not in str(ex).lower() and "cryptography" not in str(ex).lower():
                continue
            err, failed = ex, mod; break
        except Exception as ex:
            err, failed = ex, mod; break
    if err is None:
        print("  AD runtime chain (impacket/ldapdomaindump/dns): OK")
        return
    c(f"  [!] AD runtime import FAILS at {failed} ({err.__class__.__name__}: {err}) "
      "— noPac/sAMAccountName will NO-RESULT at runtime.", "1;31")
    e = err
    try:
        import site, cryptography
        path = getattr(cryptography, "__file__", "") or ""
        ver = getattr(cryptography, "__version__", "?")
        usersite = site.getusersitepackages() if hasattr(site, "getusersitepackages") else ""
        if "asn1" in str(e).lower() or "cryptography" in str(e).lower():
            if usersite and path.startswith(usersite):
                print(f"      cause: a user-site cryptography {ver} is shadowing the system one.")
                print(f"      FIX:  rm -rf {usersite}/cryptography*")
            else:
                print(f"      cryptography {ver} at {path} — upgrade it:")
                print(f"      FIX:  {sys.executable} -m pip install --upgrade cryptography")
    except Exception:
        print(f"      try: {sys.executable} -m pip install --upgrade impacket cryptography")


def install_active():
    c("\nInstalling ACTIVE-establishment tooling (--with-active)...", "1;33")
    r_update = run(sudo(["apt-get", "update"]))
    if r_update.returncode != 0:
        c(f"  [!] 'apt-get update' failed (exit {r_update.returncode})", "1;31")
    still_missing = []
    for pkg in ACTIVE_APT:
        if apt_installed(pkg):
            print(f"  {pkg}: already installed")
            continue
        print(f"  installing {pkg}…")
        run(sudo(["apt-get", "install", "-y", pkg]))
        ok = apt_installed(pkg)
        if not ok and pkg == "ptunnel-ng":
            run(sudo(["apt-get", "install", "-y", "ptunnel"]))   # older name
            ok = apt_installed("ptunnel")
        if not ok:
            print(f"  [!] {pkg} not available via apt — install manually if you need it.")
            still_missing.append(pkg)
    c("\n  Active tools with no distro package (install if you need that module):", "1;33")
    for tool, where in ACTIVE_MANUAL.items():
        have = "present" if shutil.which(tool) else "MISSING"
        print(f"   - {tool:<9} [{have}] — {where}")
    return still_missing


def main():
    with_active = "--with-active" in sys.argv[1:]
    c("=== Harness bootstrap ===", "1;32")
    missing = install_core()
    ensure_impacket_module()
    ensure_impacket_runtime()
    if with_active:
        missing += install_active()
    else:
        print("\n(active-establishment tools NOT installed — re-run with --with-active "
              "if you'll use --active)")

    if missing:
        c(f"\n[FAILED] {len(missing)} package(s) still missing after install: "
          f"{', '.join(missing)}", "1;31")
        print("  Re-run the apt command yourself to see the real error, e.g.:")
        print(f"    sudo apt-get install -y {' '.join(missing)}")
        print("  Common causes: no internet, a broken/outdated repo list, a GPG key")
        print("  error, or 'sudo' needing a password this script can't supply non-")
        print("  interactively. Fix that, then re-run bootstrap.py.")
        sys.exit(1)

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
