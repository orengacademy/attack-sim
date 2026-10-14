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
    "nmap",              # nmap_policy_scan — port-policy violation scan (was missing)
    "dnsutils",          # dig — covert_channel / DNS checks
    "openssh-client",    # ssh — ssh_over_443 (--active) and general use
    "faketime",          # kerberoast — auto-correct DC clock skew (KRB_AP_ERR_SKEW), no root
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


# Package -> a binary it provides. Lets us treat a package as satisfied when its
# tool is on PATH even if dpkg doesn't report the exact package name — the common
# case for TRANSITIONAL/renamed packages (Kali: dnsutils -> bind9-dnsutils; `dig`
# is present but `dpkg -s dnsutils` fails, which was reported as a false FAILED).
PKG_BINARY = {
    "dnsutils": "dig", "snmp": "snmpbulkwalk", "ldap-utils": "ldapsearch",
    "hping3": "hping3", "curl": "curl", "nmap": "nmap", "hydra": "hydra",
    "openssh-client": "ssh", "faketime": "faketime", "libcap2-bin": "setcap",
}


def _satisfied(pkg):
    """True if the package is installed, OR a binary it provides is on PATH (handles
    transitional/renamed packages), OR its known alias is installed."""
    if apt_installed(pkg):
        return True
    b = PKG_BINARY.get(pkg)
    if b and shutil.which(b):
        return True
    alias = APT_ALIASES.get(pkg)
    return bool(alias and apt_installed(alias))


def _which_missing(pkgs):
    """Re-check after install that each package is actually satisfied (binary on PATH
    or dpkg-installed), so a transitional-package rename or a PATH/shell difference
    isn't silently swallowed — and isn't a FALSE failure either."""
    return [p for p in pkgs if not _satisfied(p)]


def sudo(cmd):
    # root check is POSIX-only; on Windows this helper is never reached (main()
    # bails early on a non-apt OS) but guard anyway so an import/call can't crash.
    is_root = getattr(os, "geteuid", lambda: 1)() == 0
    return cmd if is_root else ["sudo"] + cmd


def apt_installed(pkg):
    r = subprocess.run(["dpkg", "-s", pkg], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    return r.returncode == 0


# Some CORE packages are Kali names; on Debian/Ubuntu fall back to these.
# impacket-scripts -> python3-impacket (which ships the impacket-* wrappers on
# Debian). responder has no Debian package (Kali-only) -> None (reported, non-fatal).
APT_ALIASES = {"impacket-scripts": "python3-impacket", "responder": None,
               "dnsutils": "bind9-dnsutils"}  # dnsutils is transitional on Kali/modern Debian


def _apt_install_one(pkg):
    """Install one apt package; if apt can't locate it, try a known distro alias.
    Returns True if the package (or its provided binary / alias) ends up satisfied."""
    if _satisfied(pkg):
        return True
    if run(sudo(["apt-get", "install", "-y", pkg])).returncode == 0 and _satisfied(pkg):
        return True
    alias = APT_ALIASES.get(pkg)
    if alias:
        print(f"  {pkg} unavailable via apt — trying {alias}")
        return run(sudo(["apt-get", "install", "-y", alias])).returncode == 0 and _satisfied(pkg)
    return False


def install_core():
    c("Checking CORE APT packages...")
    missing = [p for p in CORE_APT if not _satisfied(p)]
    if not missing:
        print("  all core APT packages already installed.")
        return []
    print("  missing:", ", ".join(missing))
    r_update = run(sudo(["apt-get", "update"]))
    if r_update.returncode != 0:
        c(f"  [!] 'apt-get update' failed (exit {r_update.returncode}) — installs below "
          f"may use a stale/broken package list.", "1;31")
    # Install INDIVIDUALLY so one package apt can't locate (e.g. the Kali-only
    # 'responder' on Debian) doesn't abort the whole batch — the old `install -y
    # <all>` left hydra/ldap-utils/hping3/dnsutils uninstalled because of it.
    for pkg in missing:
        if not _apt_install_one(pkg):
            print(f"  [!] {pkg} not installable here (Kali-only? no usable alias)")
    still_missing = _which_missing(missing)
    # A Kali-only package (alias explicitly None, e.g. responder) has no Debian
    # package — report it but DON'T fail the bootstrap over it, or a clean
    # Debian/Ubuntu run exits 1 even though every genuinely-core tool installed.
    kali_only = {p for p, a in APT_ALIASES.items() if a is None}
    optional = [p for p in still_missing if p in kali_only]
    fatal = [p for p in still_missing if p not in kali_only]
    if optional:
        c(f"  [i] optional Kali-only package(s) not installed (non-fatal): "
          f"{', '.join(optional)}", "0;33")
    if fatal:
        c(f"  [!] still missing after install attempt: {', '.join(fatal)}", "1;31")
    return fatal


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


def install_py_requirements():
    """Ensure the in-process modules' Python libs (requirements.txt / the single
    source of truth core.PY_PACKAGES) are importable; pip-install any that are
    MISSING (so apt-provided ones aren't clobbered). Upgrading a user-site
    cryptography here also clears the stale-shadow case."""
    try:
        import importlib
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import core
        pkgs = core.PY_PACKAGES
    except Exception as e:
        print(f"  (skipping requirements check: {e})")
        return
    c("\nChecking Python packages (requirements.txt) for the in-process AD modules…")
    missing = []
    for imp, pip_name in pkgs:
        try:
            importlib.import_module(imp)
            print(f"  [OK] {pip_name}")
        except Exception as e:
            print(f"  [missing/broken] {pip_name} (import {imp} -> {e.__class__.__name__})")
            missing.append(pip_name)
    missing = list(dict.fromkeys(missing))
    if not missing:
        return
    print("  installing:", ", ".join(missing))
    r = run([sys.executable, "-m", "pip", "install", "--user"] + missing)
    if r.returncode != 0:
        run([sys.executable, "-m", "pip", "install", "--user",
             "--break-system-packages"] + missing)


def grant_raw_caps():
    """Give hping3 cap_net_raw+cap_net_admin so the ICMP/SYN-flood modules run WITHOUT
    per-run sudo — the clean fix for 'needs root' (otherwise `sudo -n` fails on a box
    with no NOPASSWD rule and the flood is misreported). Best-effort: needs setcap
    (libcap2-bin) + sudo, and a filesystem that supports file caps. Where it can't
    (e.g. WSL/overlay), the modules still fall back to `sudo -n` / root."""
    c("Granting hping3 raw-socket capability (so DoS floods need no per-run sudo)...")
    hp = shutil.which("hping3")
    if not hp:
        print("  hping3 not installed — skipping (install it first).")
        return
    if not shutil.which("setcap"):
        run(sudo(["apt-get", "install", "-y", "libcap2-bin"]))   # provides setcap/getcap
    if not shutil.which("setcap"):
        print("  setcap unavailable (install libcap2-bin) — hping3 will use `sudo -n` / root instead.")
        return
    rc = run(sudo(["setcap", "cap_net_raw,cap_net_admin+eip", hp])).returncode
    if rc == 0:
        print(f"  ok: {hp} now has cap_net_raw — icmp_flood/syn_flood run unprivileged.")
    else:
        print(f"  [i] setcap failed (exit {rc}) — likely a filesystem without file-cap support "
              "(WSL/overlay). hping3 will fall back to `sudo -n` / root (cache it with "
              "`sudo -v`, or add a NOPASSWD rule).")


def main(with_active=None):
    # with_active: True/False from a caller (e.g. cli.py --bootstrap [--active]); None
    # => read the --with-active CLI flag as before when run standalone.
    if with_active is None:
        with_active = "--with-active" in sys.argv[1:]
    c("=== Harness bootstrap ===", "1;32")
    # bootstrap is the Kali/Debian APT setup helper. On Windows / non-apt Linux,
    # install the tools with your own package manager — `python3 preflight.py`
    # prints the exact winget/choco/dnf/pacman/brew command for whatever's missing.
    # The harness ENGINE itself is pure-stdlib and runs on any OS regardless.
    if not shutil.which("apt-get"):
        c("This box has no apt-get. bootstrap only automates the Kali/Debian apt "
          "setup; the harness itself runs anywhere.", "1;33")
        print("  Install the per-module tools with your OS package manager, then:")
        print("    python3 preflight.py      # lists exactly what's missing + the install command")
        print("  (impacket on any OS: python3 -m pip install impacket)")
        return
    missing = install_core()
    ensure_impacket_module()
    install_py_requirements()
    ensure_impacket_runtime()
    grant_raw_caps()          # hping3 cap_net_raw so the flood modules need no per-run sudo
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
    print("  (ICMP/SYN flood, PetitPotam, stateful_evasion) need raw sockets.")
    print("  hping3 was setcap'd above, so icmp_flood/syn_flood run WITHOUT sudo. If that")
    print("  step reported a failure (e.g. WSL/overlay FS), enable elevation via ONE of:")
    print("   - setcap (hping3 floods): sudo setcap cap_net_raw,cap_net_admin+eip $(which hping3)")
    print("   - cache sudo (~15 min):   sudo -v   (then the modules' `sudo -n` succeeds)")
    print("   - NOPASSWD sudoers:       <user> ALL=(root) NOPASSWD: $(command -v hping3), $(command -v responder)")
    c("\nCredentials: set HARNESS_DC_PASS (and HARNESS_DOMAIN/HARNESS_DC_USER),", "1;32")
    print("  or copy credentials.env.example -> credentials.env and fill it in.")
    c("USS infra: copy config.json.example -> config.json for your VPS/domain/canary;", "1;32")
    print("  detections.json for the DETECTED verdict. Check readiness: python3 preflight.py")
    c("\nNow run:  python3 gui.py   (or: python3 cli.py --list)", "1;32")


if __name__ == "__main__":
    main()
