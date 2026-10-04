"""_impacket.py — resolve an impacket example tool across packaging flavours.

The same impacket script is called different things depending on how impacket was
installed, so hard-coding the Kali name made modules PREREQ-MISSING elsewhere:
  - Kali 'impacket-scripts' : impacket-GetUserSPNs
  - pip 'impacket' (fortra) : GetUserSPNs.py   (console_scripts)
  - some distros            : GetUserSPNs

resolve("GetUserSPNs") returns the first of those found on PATH, else None — so a
module can run whichever exists instead of relying on one tool name. If none is on
PATH but the impacket PYTHON lib is importable, the caller can still drive it in
process. Leading underscore -> not an attack module (loader skips it).
"""
import os
import shutil
import sys

_CANDIDATES = ("impacket-{b}", "{b}.py", "{b}")

# Where distros drop the impacket example scripts when they're not on PATH
# (Debian's python3-impacket puts them under /usr/share/doc; pip under the pkg).
def _example_dirs():
    dirs = ["/usr/share/doc/python3-impacket/examples",
            "/usr/share/doc/impacket/examples"]
    try:
        import impacket
        base = os.path.dirname(os.path.dirname(impacket.__file__))
        dirs += [os.path.join(base, "impacket", "examples"),
                 os.path.join(base, "..", "share", "doc", "impacket", "examples")]
    except Exception:
        pass
    return dirs


def resolve(base):
    """A runnable command for an impacket example tool, or None. Tries PATH names
    (impacket-X / X.py / X) first, then runs the example script directly via the
    current python (python3 /path/X.py) — so a module never depends on the Kali
    CLI wrapper being installed, only on the impacket library being present."""
    for pat in _CANDIDATES:
        name = pat.format(b=base)
        if shutil.which(name):
            return name
    for d in _example_dirs():
        p = os.path.join(d, f"{base}.py")
        if os.path.isfile(p):
            # quote the interpreter+path so it survives shlex.split in run_cmd
            return f'"{sys.executable}" "{p}"'
    return None


def script_path(base):
    """The FILESYSTEM path of an impacket example script (``X.py``), for modules
    that load a class OUT of it via importlib (spec_from_file_location) rather than
    shelling out — e.g. wmiexec/psexec on a Kali/Debian layout where the examples
    ship only as doc scripts. Returns None if not found. Prefer importing
    ``impacket.examples.X`` directly where that package layout exists (pip/source)."""
    for d in _example_dirs():
        p = os.path.join(d, f"{base}.py")
        if os.path.isfile(p):
            return p
    return None


def have_lib():
    """True if the impacket PYTHON library is importable (the real dependency)."""
    try:
        import impacket  # noqa: F401
        return True
    except Exception:
        return False
