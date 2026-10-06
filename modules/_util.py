"""Shared helpers for the USS attack-sim modules.

The loader skips any file starting with '_', so this is NOT discovered as an
attack module — it's a small utility library the real modules import via
`from modules import _util as U`.

Everything here is non-destructive and cross-platform where it can be. Helpers
honour ctx.source_ip (bind egress to a specific interface / VRF for the
assumed-breach foothold #2) and never raise — they return a (bool, detail) or a
string so a module can compose its own output/verdict.
"""
import socket
import ssl
import shutil
import subprocess
import time
import threading


def have(tool):
    """True if an external binary is on PATH."""
    return shutil.which(tool) is not None


def _src(ctx):
    return (ctx.source_ip, 0) if (ctx and getattr(ctx, "source_ip", None)) else None


def connect(host, port, ctx=None, timeout=6):
    """Plain TCP connect honouring ctx.source_ip. Raises like create_connection."""
    return socket.create_connection((host, port), timeout=timeout,
                                    source_address=_src(ctx))


def tcp_state(host, port, ctx=None, timeout=4):
    """open / refused / filtered / unresolved / unreachable for one TCP port."""
    try:
        with connect(host, port, ctx, timeout):
            return "open"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except ConnectionRefusedError:
        return "refused"
    except socket.gaierror:
        return "unresolved"
    except OSError:
        return "unreachable"


def tls_reachable(host, port=443, ctx=None, timeout=6, server_hostname=None):
    """(reachable, detail). Completes a TLS handshake; egress is 'reachable' even
    on a TLS-level error (the bytes got out and back), but not on a
    timeout/refused/DNS failure (the boundary stopped it)."""
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        with connect(host, port, ctx, timeout) as raw:
            with c.wrap_socket(raw, server_hostname=server_hostname or host) as t:
                return True, f"TLS {t.version()} established"
    except ssl.SSLError as e:
        return True, f"reached (TLS error {e.__class__.__name__})"
    except (socket.timeout, TimeoutError):
        return False, "timed out (blocked/filtered)"
    except socket.gaierror:
        return False, "DNS did not resolve (blocked / forced internal resolver)"
    except ConnectionRefusedError:
        return False, "refused (no listener)"
    except OSError as e:
        return False, f"unreachable ({e.__class__.__name__})"


def udp_egress(host, port, ctx=None, payload=b"\x00", timeout=4):
    """Best-effort UDP egress probe: 'reply' / 'sent (no reply)' / 'refused' /
    'blocked'. UDP has no handshake, so 'sent (no reply)' is the common case and
    still means the datagram was accepted for egress by the local stack."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if ctx and getattr(ctx, "source_ip", None):
            try:
                s.bind((ctx.source_ip, 0))
            except OSError:
                pass
        s.sendto(payload, (host, port))
        try:
            s.recvfrom(2048)
            return "reply"
        except socket.timeout:
            return "sent (no reply)"
        except ConnectionRefusedError:
            return "refused"
    except socket.gaierror:
        return "unresolved"
    except OSError as e:
        return f"blocked ({e.__class__.__name__})"
    finally:
        s.close()


def run_transient(argv, seconds, look_for=None):
    """Launch a long-lived client (a tunnel/beacon), let it run up to `seconds`
    (or until a `look_for` keyword appears in its output), then ALWAYS terminate
    it. Returns (tail_output, matched). Used by active-establishment modules so
    they never leave a process behind. `look_for` is a list of case-insensitive
    substrings signalling success (e.g. ['connected','tunnel']).
    """
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        return f"[ERROR] {argv[0]} not found", False
    except Exception as e:
        return f"[ERROR] could not launch {argv[0]}: {e}", False

    out = []
    matched = {"v": False}

    def reader():
        try:
            for line in p.stdout:
                out.append(line.rstrip())
                if look_for and any(k.lower() in line.lower() for k in look_for):
                    matched["v"] = True
        except Exception:
            pass

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    t0 = time.time()
    while time.time() - t0 < seconds and p.poll() is None and not matched["v"]:
        time.sleep(0.3)
    # tear down — terminate, then kill if it ignores us
    try:
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    except Exception:
        pass
    return "\n".join(out[-50:]) or "(no output)", matched["v"]


def dns_query(qname, server, ctx=None, timeout=4, rrtype=1):
    """Send one minimal DNS query for qname to `server` (UDP/53) with no external
    tools, honouring ctx.source_ip. Returns (egressed, detail): egressed=True if
    ANY DNS response came back (NOERROR/NXDOMAIN both count — the query left and a
    resolver answered), False if it timed out / was blocked. rrtype 1=A, 16=TXT.
    """
    import struct
    import os
    tid = os.getpid() & 0xFFFF
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".") if l) + b"\x00"
    packet = header + q + struct.pack(">HH", rrtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if ctx and getattr(ctx, "source_ip", None):
            try:
                s.bind((ctx.source_ip, 0))
            except OSError:
                pass
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(2048)
        rcode = data[3] & 0x0F if len(data) >= 4 else -1
        names = {0: "NOERROR", 3: "NXDOMAIN", 2: "SERVFAIL", 5: "REFUSED"}
        return True, f"answered rcode={names.get(rcode, rcode)}"
    except socket.timeout:
        return False, "timed out (query did not egress / no resolver)"
    except socket.gaierror:
        return False, "server name did not resolve"
    except OSError as e:
        return False, f"blocked ({e.__class__.__name__})"
    finally:
        s.close()


def skip(reason):
    """Standard '[SKIP]' line — surfaced by the classifier as the NO-RESULT hint
    (used when an active module has no infra configured / --active is off)."""
    return f"[SKIP] {reason}"


def ntlm_md4_available():
    """True if MD4 (the NT-hash primitive ldap3's NTLM bind needs) can be computed.
    pycryptodome provides it; modern OpenSSL (3.x — current Kali/Debian) DISABLES
    md4 in hashlib, so without pycryptodome the bind dies with 'unsupported hash
    type MD4'. Checked up front so noPac / sAMAccountName report a clear
    PREREQ-MISSING instead of a cryptic NO-RESULT crash."""
    try:
        from Crypto.Hash import MD4  # noqa: F401  (pycryptodome)
        return True
    except Exception:
        pass
    try:
        import hashlib
        hashlib.new("md4")
        return True
    except Exception:
        return False


MD4_PREREQ_HINT = ("[PREREQ-MISSING] NTLM needs MD4, which isn't available here — "
                   "install pycryptodome (`pip install pycryptodome`; modern OpenSSL "
                   "disables md4 in hashlib). See requirements.txt.")
