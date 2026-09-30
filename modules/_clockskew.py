"""
_clockskew.py — protocol-native Kerberos clock-skew auto-correction.

Kerberos requires the client and KDC clocks to agree within a small
window (default 5 min) or every AS-REQ/TGS-REQ fails with
KRB_AP_ERR_SKEW. Rather than requiring every engineer running this
harness to `sudo date -s ...` their own box to match the lab DC (not
scalable — see the module chat history), this measures the offset from
the KDC's OWN clock and applies it only inside this process, only for the
duration of one attack — no root, no system clock change, no dependency
on SSH/NTP access to the target.

How: Kerberos' protocol itself hands you the fix. Any KRB-ERROR response
(even from a deliberately-bogus AS-REQ — wrong user is fine, we're not
authenticating) carries the KDC's own `stime`/`susec` fields — that's
the whole mechanism real Kerberos clients use to detect skew in the
first place. We read that, compute the offset against our local clock,
then monkeypatch the `datetime` name *as seen from inside* the specific
modules that generate Kerberos request timestamps — not the real global
`datetime` module, so nothing outside those modules (TLS, logging
timestamps, anything else on this box) is affected.

Usage (see modules/nopac.py):
    offset = _clockskew.measure_offset(target)
    if offset is not None:
        _clockskew.install(offset)
    try:
        ...  # Kerberos-dependent calls
    finally:
        _clockskew.remove()
"""
import datetime as _dt
import importlib
import sys
import types

# Modules that build their own Kerberos request timestamps via
# datetime.datetime.now()/utcnow() and need the patched clock. Referenced
# by their sys.modules key, so the vendored noPac utils.* (loaded via
# modules/nopac.py's own importlib trick, before install() is called)
# resolve correctly too.
PATCHED_MODULES = [
    "impacket.krb5.kerberosv5",
    "impacket.examples.utils",
    "utils.S4U2self",  # vendored noPac module — only present once noPac.py itself has been loaded
]

_originals = {}


class _OffsetDatetime(_dt.datetime):
    _offset = _dt.timedelta(0)

    @classmethod
    def now(cls, tz=None):
        return _dt.datetime.now(tz) + cls._offset

    @classmethod
    def utcnow(cls):
        return _dt.datetime.utcnow() + cls._offset


def measure_offset(target, kdc_port=88, timeout=10):
    """Return (kdc_time - local_time) as a timedelta, or None if the KDC
    couldn't be reached at all (as opposed to just rejecting our probe,
    which is expected and fine — we only need the error packet)."""
    from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    try:
        getKerberosTGT(
            Principal("_clockprobe_", type=constants.PrincipalNameType.NT_PRINCIPAL.value),
            "", "_clockprobe_.invalid", None, None, None, kdcHost=target,
        )
    except KerberosError as e:
        pkt = e.getErrorPacket()
        kdc_time = _dt.datetime.strptime(str(pkt["stime"]), "%Y%m%d%H%M%SZ").replace(
            tzinfo=_dt.timezone.utc, microsecond=int(pkt["susec"])
        )
        return kdc_time - _dt.datetime.now(_dt.timezone.utc)
    except Exception:
        return None
    # A KerberosTGT that somehow succeeds outright means clocks were
    # already fine — no correction needed.
    return _dt.timedelta(0)


def install(offset):
    _OffsetDatetime._offset = offset
    for modname in PATCHED_MODULES:
        mod = sys.modules.get(modname)
        if mod is None:
            try:
                mod = importlib.import_module(modname)
            except ImportError:
                continue  # not loaded (e.g. vendored module not imported yet) — nothing to patch
        if modname not in _originals:
            _originals[modname] = getattr(mod, "datetime", None)
        shim = types.ModuleType("datetime")
        for name in dir(_dt):
            if not name.startswith("_"):
                setattr(shim, name, getattr(_dt, name))
        shim.datetime = _OffsetDatetime
        mod.datetime = shim


def remove():
    for modname, orig in _originals.items():
        mod = sys.modules.get(modname)
        if mod is not None and orig is not None:
            mod.datetime = orig
    _originals.clear()
