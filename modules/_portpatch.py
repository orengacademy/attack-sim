"""
_portpatch.py — shared socket.connect() redirect for NAT'd lab targets.

Factored out of test2.py (see that file's docstring for the full writeup).
Some lab targets only expose SMB(445)/RPC(135) via forwarded alternates
(e.g. a DigitalOcean droplet DNAT'ing external 4445 -> target:445 and
1135 -> target:135). impacket hardcodes those destination ports inside
its own connection logic, so modules that talk to such a target need this
patch installed before they open any socket.

Leading underscore -> loader.py's auto-discovery skips this file (it's
not itself an attack module); import it from modules/*.py as needed:

    from modules import _portpatch
    ...
    is_custom = _portpatch.is_custom_port_target(target)
    if is_custom:
        _portpatch.install(target)
    try:
        ...
    finally:
        if is_custom:
            _portpatch.remove()

Only entries in CUSTOM_PORT_TARGETS get rewritten — any other target_ip
passes straight through untouched, so ordinary directly-reachable lab
targets are unaffected. Add an entry here when a new NAT'd target shows up.
"""
import socket

CUSTOM_PORT_TARGETS = {
    # target_ip: {real_port: forwarded_port, ...}
    "159.223.35.108": {445: 4445, 135: 1135},
}

_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex


def is_custom_port_target(target_ip):
    return target_ip in CUSTOM_PORT_TARGETS


def _rewrite(target_ip, address):
    port_map = CUSTOM_PORT_TARGETS.get(target_ip)
    if not port_map or not isinstance(address, tuple) or len(address) != 2:
        return address
    host, port = address
    if host == target_ip and port in port_map:
        new_port = port_map[port]
        print(f"    [patch] redirecting {host}:{port} -> {host}:{new_port}")
        return (host, new_port)
    return address


def install(target_ip):
    """Patch socket.socket.connect/connect_ex for the duration of one
    attack. Rewrites are scoped to target_ip via CUSTOM_PORT_TARGETS, so
    installing this while talking to an unlisted host is a no-op."""
    def _patched_connect(self, address):
        return _original_connect(self, _rewrite(target_ip, address))

    def _patched_connect_ex(self, address):
        return _original_connect_ex(self, _rewrite(target_ip, address))

    socket.socket.connect = _patched_connect
    socket.socket.connect_ex = _patched_connect_ex


def remove():
    socket.socket.connect = _original_connect
    socket.socket.connect_ex = _original_connect_ex
