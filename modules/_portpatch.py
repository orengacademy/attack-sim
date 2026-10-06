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

# The CANONICAL cloud NAT map (SMB 445->4445, RPC 135->1135, SSH 22->2222). The
# cloud/on-prem distinction is a property of the TARGET, not of a toggle: these are
# the ONLY NAT'd cloud DCs, so they ALWAYS use the alternates and every other target
# ALWAYS uses the real 445/135. core.is_cloud_target() reads CLOUD_TARGETS, and the
# front-ends force cloud for these IPs (and never clear their mapping) so the AD
# modules can't be pointed at the dead raw 445/135 and wrongly score BLOCKED.
CLOUD_NAT_MAP = {445: 4445, 135: 1135, 22: 2222}
# MyGovNet cloud DCs (DigitalOcean) — the ONLY cloud targets. KVDC/IPDC on-prem DCs
# are NOT listed, so they pass straight through on the real 445/135. Everything else
# (LDAP 389/636, Kerberos 88, GC 3268/3269, RDP 3389) is standard on both.
CLOUD_TARGETS = ("159.223.35.108", "167.71.222.169")

# Live per-target map the front-ends mutate for a run. SEEDED from the canonical
# cloud set; a canonical cloud target's entry must never be removed (see core).
# NOTE: the socket.connect monkeypatch only redirects IN-PROCESS sockets (impacket);
# subprocess tools (hydra for ssh_brute) read the alt port from this map directly.
CUSTOM_PORT_TARGETS = {ip: dict(CLOUD_NAT_MAP) for ip in CLOUD_TARGETS}


def is_cloud_target(target_ip):
    """True iff this IP is a CANONICAL cloud target (always NAT'd 4445/1135)."""
    return str(target_ip or "").strip() in CLOUD_TARGETS


def canonical_cloud_map(target_ip, ssh_port=None):
    """The NAT map a canonical cloud target must use: SMB 445->4445, RPC 135->1135,
    and SSH 22->ssh_port (default 2222). Returns None for a non-cloud target."""
    if not is_cloud_target(target_ip):
        return None
    m = dict(CLOUD_NAT_MAP)
    if ssh_port:
        m[22] = int(ssh_port)
    return m
# Default cloud SSH alternate port, used by the CLI/GUI when registering a cloud
# target so ssh_brute hits the forwarded SSH port.
DEFAULT_CLOUD_SSH_PORT = 2222

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
