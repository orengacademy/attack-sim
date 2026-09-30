"""
_dcompatch.py — DCOM/WMI OXID-resolver NAT fix, for the same NAT'd lab
targets as modules/_portpatch.py.

DRSUAPI/DCSync only had ONE NAT problem: the endpoint mapper hands back a
*port* number, and our socket patch rewrites the destination port before
connecting. WMI/DCOM is worse: the OXID resolver hands back a full
string binding — an *address* (usually the server's own internal IP, or
its hostname) *and* a port — for every COM object it creates
(impacket.dcerpc.v5.dcomrt.INTERFACE.connect()). impacket only accepts a
binding whose address literally matches the target we connected with; a
NAT'd target reports its real internal IP (e.g. 192.168.122.x) there,
which doesn't match our target_ip string at all and isn't reachable
regardless, so impacket raises "Can't find a valid stringBinding to
connect" before even getting to a port problem _portpatch.py could fix.

Fix: patch CLASS_INSTANCE.get_string_bindings() (impacket.dcerpc.v5.dcomrt)
to rewrite the address portion of every returned binding to target_ip,
keeping the port impacket already discovered. That's the exact string
impacket's own connect() builds when it DOES manage to resolve a target
by hostname (see its `isTargetFQDN` branch) — we're just forcing that
substitution unconditionally, since we already know (same as
_portpatch.py) that everything for this target actually needs to go to
target_ip regardless of what internal address the DC reports about
itself.

Usage (see modules/wmiexec.py):
    is_custom = _portpatch.is_custom_port_target(target)
    if is_custom:
        _portpatch.install(target)
        _dcompatch.install(target)
    try:
        ...
    finally:
        if is_custom:
            _dcompatch.remove()
            _portpatch.remove()
"""
from impacket.dcerpc.v5.dcomrt import CLASS_INSTANCE

_original_get_string_bindings = CLASS_INSTANCE.get_string_bindings


def install(target_ip):
    def _patched(self):
        bindings = _original_get_string_bindings(self)
        for b in bindings:
            if b["wTowerId"] != 7:
                continue
            addr = str(b["aNetworkAddr"])
            if "[" in addr:
                _, bracket, rest = addr.partition("[")
                port_part = bracket + rest  # "[port]\x00"
            else:
                port_part = "\x00"
            new_addr = target_ip + port_part
            print(f"    [dcom-patch] rewriting OXID string binding {addr!r} -> {new_addr!r}")
            b["aNetworkAddr"] = new_addr
        return bindings

    CLASS_INSTANCE.get_string_bindings = _patched


def remove():
    CLASS_INSTANCE.get_string_bindings = _original_get_string_bindings
