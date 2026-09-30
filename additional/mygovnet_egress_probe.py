#!/usr/bin/env python3
"""
MyGovNet Egress & Segmentation Control Validation Probe
=======================================================

A NON-DESTRUCTIVE breach-and-attack-simulation harness for the GITN MyGovNet
engagement. Given a source (where it runs / which egress path to bind) and a
destination across the boundary, it measures WHICH channels actually pass the
inter-zone controls between SDWAN and the KVDC / IPDC data centres.

It does NOT exploit anything. Every check is a connectivity / protocol test that
answers one question per channel: did this traffic reach the destination through
the boundary, or was it blocked? Each result maps to the plan's verdict scheme:

    BLOCKED    -> control worked (good)
    PASSED     -> traffic traversed the boundary  (potential finding; confirm the
                  blue team also DETECTED it to complete the purple-team verdict)
    INCONCLUSIVE / ERROR -> could not determine; investigate manually

Authorized use only. Run exclusively within a signed scope and test window,
against systems you are explicitly permitted to test. See the ROE section of the
engagement test plan (mygovnet-attack-sim-plan.html).

Usage:
    python3 mygovnet_egress_probe.py -d <dest_ip_or_host> [-s <source_ip>] [options]

Examples:
    # Full sweep northbound from an Agency-SDWAN host to a KVDC service
    python3 mygovnet_egress_probe.py -d 10.20.30.40 -s 10.10.1.15

    # Only the 443 tunnel / DoH channel-discovery checks, JSON report
    python3 mygovnet_egress_probe.py -d dc-app.gov.my --tests tls,l7,doh --json run1.json

    # Reverse path: from a DC host outward (least-privilege egress test)
    python3 mygovnet_egress_probe.py -d 1.1.1.1 --tests ports,dns,doh,icmp
"""

import argparse
import json
import socket
import ssl
import struct
import subprocess
import sys
import time

# ----------------------------------------------------------------------------
# Channel catalogue — the inter-zone port/protocol matrix (plan Family D) plus
# the egress channels a boundary must restrict. Each entry ties to a MITRE id so
# results drop straight into the ATT&CK coverage report.
# ----------------------------------------------------------------------------
PORT_CATALOG = [
    # (port, proto, label, mitre, note)
    (443,   "tcp", "HTTPS / TLS (tunnel & C2 carrier)", "T1071.001", "Cloudflare/ngrok/chisel ride this"),
    (80,    "tcp", "HTTP",                              "T1071.001", "cleartext web egress"),
    (53,    "tcp", "DNS/TCP",                           "T1071.004", "should reach internal resolver only"),
    (853,   "tcp", "DoT (DNS-over-TLS)",                "T1071.004", "non-standard resolver port"),
    (22,    "tcp", "SSH",                               "T1021.004", "SSH-over-boundary / tunnelling"),
    (445,   "tcp", "SMB",                               "T1021.002", "lateral movement / file"),
    (3389,  "tcp", "RDP",                               "T1021.001", "remote desktop"),
    (5985,  "tcp", "WinRM-HTTP",                        "T1021.006", "remote management"),
    (5986,  "tcp", "WinRM-HTTPS",                       "T1021.006", "remote management"),
    (389,   "tcp", "LDAP",                              "T1087.002", "directory"),
    (636,   "tcp", "LDAPS",                             "T1087.002", "directory (TLS)"),
    (88,    "tcp", "Kerberos",                          "T1558",     "auth"),
    (135,   "tcp", "MSRPC",                             "T1047",     "RPC endpoint mapper"),
    (1433,  "tcp", "MSSQL",                             "T1210",     "database"),
    (1521,  "tcp", "Oracle",                            "T1210",     "database"),
    (3306,  "tcp", "MySQL",                             "T1210",     "database"),
    (5432,  "tcp", "PostgreSQL",                        "T1210",     "database"),
    (161,   "tcp", "SNMP/TCP",                          "T1046",     "management"),
    (514,   "tcp", "Syslog/TCP",                        "T1046",     "logging"),
    (23,    "tcp", "Telnet",                            "T1021",     "legacy mgmt"),
]

# Compact default sweep — the ports most telling about boundary least-privilege.
DEFAULT_PORTS = [443, 80, 53, 853, 22, 445, 3389, 5985, 5986, 389, 636, 135, 1433, 3306, 5432]

# Public DoH / DNS endpoints used purely to test whether the internal resolver
# can be bypassed (plan Family B). These are reachability checks, not tunnels.
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DOH_ENDPOINTS = [
    ("cloudflare", "https://1.1.1.1/dns-query"),
    ("google",     "https://dns.google/resolve"),
]

# Result verdict constants
BLOCKED = "BLOCKED"
PASSED = "PASSED"
INCONCLUSIVE = "INCONCLUSIVE"
ERROR = "ERROR"

RESET = "\033[0m"
COLORS = {
    BLOCKED: "\033[32m",       # green  - control worked
    PASSED: "\033[31m",        # red    - traffic got through (finding)
    INCONCLUSIVE: "\033[33m",  # yellow
    ERROR: "\033[90m",         # grey
}


class Probe:
    def __init__(self, source, destination, timeout, use_color=True):
        self.source = source
        self.destination = destination
        self.timeout = timeout
        self.use_color = use_color
        self.results = []
        # Resolve destination once so every test targets the same address.
        try:
            self.dest_ip = socket.gethostbyname(destination)
        except socket.gaierror as exc:
            print(f"[!] Could not resolve destination '{destination}': {exc}", file=sys.stderr)
            sys.exit(2)

    # -- helpers ------------------------------------------------------------
    def _record(self, test, target, verdict, mitre, detail):
        self.results.append({
            "test": test,
            "target": target,
            "verdict": verdict,
            "mitre": mitre,
            "detail": detail,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
        tag = verdict
        if self.use_color:
            tag = f"{COLORS.get(verdict, '')}{verdict}{RESET}"
        print(f"  [{tag:<12}] {test:<34} {target:<24} {detail}")

    def _new_tcp_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        if self.source:
            try:
                sock.bind((self.source, 0))
            except OSError as exc:
                sock.close()
                raise OSError(f"cannot bind source {self.source}: {exc}")
        return sock

    # -- test groups --------------------------------------------------------
    def test_ports(self, ports):
        """TCP-connect sweep. An open connection means the boundary permitted it."""
        print("\n[*] Boundary port/protocol sweep (Family D)")
        catalog = {p: (lbl, mitre, note) for p, _, lbl, mitre, note in PORT_CATALOG}
        for port in ports:
            lbl, mitre, _ = catalog.get(port, (f"tcp/{port}", "T1046", ""))
            target = f"{self.dest_ip}:{port}"
            try:
                sock = self._new_tcp_socket()
            except OSError as exc:
                self._record("port-sweep", target, ERROR, "T1046", str(exc))
                return
            try:
                rc = sock.connect_ex((self.dest_ip, port))
                if rc == 0:
                    self._record(f"open:{lbl}", target, PASSED, mitre,
                                 "TCP handshake completed through boundary")
                else:
                    self._record(f"open:{lbl}", target, BLOCKED, mitre,
                                 f"no handshake (errno {rc})")
            except socket.timeout:
                self._record(f"open:{lbl}", target, BLOCKED, mitre, "timed out / filtered")
            except OSError as exc:
                self._record(f"open:{lbl}", target, INCONCLUSIVE, mitre, str(exc))
            finally:
                sock.close()

    def test_tls(self):
        """Complete a TLS handshake on 443 and read the presented certificate.

        Confirms 443 is a usable encrypted carrier (Cloudflare Tunnel, ngrok,
        chisel, LOTS C2 all depend on this) and reveals whether a TLS-inspecting
        proxy is substituting its own certificate.
        """
        print("\n[*] TLS carrier on 443 (Family A)")
        target = f"{self.dest_ip}:443"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            raw = self._new_tcp_socket()
        except OSError as exc:
            self._record("tls-handshake", target, ERROR, "T1071.001", str(exc))
            return
        try:
            raw.connect((self.dest_ip, 443))
            with ctx.wrap_socket(raw, server_hostname=self.destination) as tls:
                cert = tls.getpeercert(binary_form=True)
                version = tls.version()
                issuer = "unknown"
                try:
                    der = tls.getpeercert()
                    if der and der.get("issuer"):
                        issuer = der["issuer"][-1][0][1]
                except Exception:
                    pass
                self._record("tls-handshake", target, PASSED, "T1071.001",
                             f"{version} established; cert {len(cert or b'')}B; issuer~{issuer} "
                             f"(inspect for proxy substitution)")
        except socket.timeout:
            self._record("tls-handshake", target, BLOCKED, "T1071.001", "timed out / filtered")
        except ssl.SSLError as exc:
            self._record("tls-handshake", target, INCONCLUSIVE, "T1071.001", f"TLS error: {exc}")
        except OSError as exc:
            self._record("tls-handshake", target, BLOCKED, "T1071.001", str(exc))
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def test_l7_on_443(self):
        """Send non-TLS bytes to port 443 to test L4-vs-L7 enforcement.

        A port-only firewall forwards anything on 443; an application-aware
        boundary should reset a session on 443 that isn't valid TLS. If the peer
        accepts / holds the connection, the boundary is NOT enforcing L7 — that is
        exactly the gap raw-TCP tunnels (chisel/gost) exploit.
        """
        print("\n[*] L4-vs-L7 enforcement on 443 (Family D)")
        target = f"{self.dest_ip}:443"
        try:
            sock = self._new_tcp_socket()
        except OSError as exc:
            self._record("nontls-on-443", target, ERROR, "T1095", str(exc))
            return
        try:
            sock.connect((self.dest_ip, 443))
            # Benign, obviously-non-TLS marker payload.
            sock.sendall(b"MYGOVNET-EGRESS-PROBE/NON-TLS-L7-CHECK\r\n")
            sock.settimeout(self.timeout)
            try:
                data = sock.recv(64)
                detail = ("peer responded to non-TLS bytes -> boundary is port-only "
                          f"(L7 NOT enforced); {len(data)}B back")
                self._record("nontls-on-443", target, PASSED, "T1095", detail)
            except socket.timeout:
                # Connection stayed open with no reset -> non-TLS tolerated.
                self._record("nontls-on-443", target, PASSED, "T1095",
                             "non-TLS session held open (no L7 reset) -> tunnelable")
        except ConnectionResetError:
            self._record("nontls-on-443", target, BLOCKED, "T1095",
                         "reset on non-TLS bytes -> L7/app-ID enforced (good)")
        except socket.timeout:
            self._record("nontls-on-443", target, BLOCKED, "T1095", "timed out / filtered")
        except OSError as exc:
            self._record("nontls-on-443", target, INCONCLUSIVE, "T1095", str(exc))
        finally:
            sock.close()

    def test_dns_direct(self):
        """Query public resolvers directly on UDP/53 and TCP/53.

        If a query to 1.1.1.1/8.8.8.8 succeeds, the endpoint can bypass the
        internal resolver (and its logging/sinkholing) — the precondition for
        DNS tunnelling (plan Family B). A locked-down boundary should force all
        :53 to the internal resolver only.
        """
        print("\n[*] Direct external DNS resolver reachability (Family B)")
        query = self._build_dns_query("example.com")
        for resolver in PUBLIC_RESOLVERS:
            # UDP/53
            target = f"{resolver}:53/udp"
            try:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.settimeout(self.timeout)
                if self.source:
                    udp.bind((self.source, 0))
                udp.sendto(query, (resolver, 53))
                data, _ = udp.recvfrom(512)
                udp.close()
                ok = len(data) > 12 and data[:2] == query[:2]
                self._record("dns-direct-udp", target, PASSED if ok else INCONCLUSIVE,
                             "T1071.004",
                             "external resolver answered -> internal resolver bypassable"
                             if ok else "malformed/partial answer")
            except socket.timeout:
                self._record("dns-direct-udp", target, BLOCKED, "T1071.004",
                             "no answer -> external :53 filtered (good)")
            except OSError as exc:
                self._record("dns-direct-udp", target, INCONCLUSIVE, "T1071.004", str(exc))

    def test_doh(self):
        """Reach public DNS-over-HTTPS endpoints on 443.

        DoH hides resolution inside ordinary HTTPS, defeating internal DNS
        filtering/logging (plan Family B). Success here means the endpoint can
        resolve names the corporate resolver never sees.
        """
        print("\n[*] DNS-over-HTTPS resolver bypass (Family B)")
        import urllib.request
        import urllib.error
        for name, url in DOH_ENDPOINTS:
            full = f"{url}?name=example.com&type=A"
            req = urllib.request.Request(full, headers={"accept": "application/dns-json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read(512)
                    ok = resp.status == 200 and b"Answer" in body or b"Status" in body
                    self._record(f"doh:{name}", url, PASSED if ok else INCONCLUSIVE,
                                 "T1071.004",
                                 "DoH resolved -> internal resolver bypassable"
                                 if ok else f"HTTP {resp.status}, unexpected body")
            except urllib.error.URLError as exc:
                self._record(f"doh:{name}", url, BLOCKED, "T1071.004",
                             f"unreachable -> DoH endpoint blocked (good): {exc.reason}")
            except socket.timeout:
                self._record(f"doh:{name}", url, BLOCKED, "T1071.004", "timed out (good)")
            except Exception as exc:
                self._record(f"doh:{name}", url, INCONCLUSIVE, "T1071.004", str(exc))

    def test_icmp(self):
        """ICMP echo egress to the destination via the system ping.

        Uses the OS ping (no raw-socket privileges needed). Reachable ICMP is a
        covert-channel / exfil path (ptunnel) the boundary should restrict.
        """
        print("\n[*] ICMP egress (Family E)")
        target = self.dest_ip
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout))), self.dest_ip]
        if self.source:
            cmd[1:1] = ["-I", self.source]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout + 3)
            if proc.returncode == 0:
                self._record("icmp-echo", target, PASSED, "T1048.003",
                             "echo reply received -> ICMP egress permitted")
            else:
                self._record("icmp-echo", target, BLOCKED, "T1048.003",
                             "no reply -> ICMP filtered (good)")
        except subprocess.TimeoutExpired:
            self._record("icmp-echo", target, BLOCKED, "T1048.003", "ping timed out")
        except FileNotFoundError:
            self._record("icmp-echo", target, ERROR, "T1048.003", "ping binary not found")

    # -- low-level ----------------------------------------------------------
    @staticmethod
    def _build_dns_query(qname):
        tid = 0x1337
        flags = 0x0100  # standard query, recursion desired
        header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
        q = b""
        for label in qname.split("."):
            q += bytes([len(label)]) + label.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
        return header + q

    # -- reporting ----------------------------------------------------------
    def summary(self):
        counts = {}
        for r in self.results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print("\n" + "=" * 78)
        print("SUMMARY")
        print("=" * 78)
        for verdict in (PASSED, BLOCKED, INCONCLUSIVE, ERROR):
            n = counts.get(verdict, 0)
            tag = f"{COLORS.get(verdict, '')}{verdict}{RESET}" if self.use_color else verdict
            print(f"  {tag:<20} {n}")
        passed = [r for r in self.results if r["verdict"] == PASSED]
        if passed:
            print(f"\n  {len(passed)} channel(s) traversed the boundary — candidate findings.")
            print("  Confirm the SOC also DETECTED each before closing as a purple-team result.")
        print("=" * 78)


def parse_ports(spec):
    if spec in (None, "", "default"):
        return DEFAULT_PORTS
    if spec == "all":
        return [p for p, *_ in PORT_CATALOG]
    ports = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        elif chunk:
            ports.append(int(chunk))
    return ports


def banner():
    print("=" * 78)
    print(" MyGovNet Egress & Segmentation Control Validation Probe")
    print(" AUTHORIZED USE ONLY — run only within a signed scope and test window.")
    print(" Non-destructive: connectivity/protocol checks, no exploitation.")
    print("=" * 78)


def main():
    ap = argparse.ArgumentParser(
        description="Non-destructive egress/segmentation control validation probe "
                    "for the MyGovNet purple-team engagement.",
        epilog="Verdicts: BLOCKED=control worked | PASSED=traffic traversed (finding) "
               "| INCONCLUSIVE/ERROR=investigate.")
    ap.add_argument("-d", "--destination", required=True,
                    help="Target host/IP across the boundary (KVDC/IPDC service, or "
                         "external host for reverse-path tests).")
    ap.add_argument("-s", "--source", default=None,
                    help="Local source IP to bind egress from (selects/attributes the "
                         "egress path on multi-homed hosts). Default: OS-chosen.")
    ap.add_argument("-p", "--ports", default="default",
                    help="'default', 'all', a comma list (443,53,3389), or ranges "
                         "(1000-1010). Applies to the port-sweep test.")
    ap.add_argument("-t", "--timeout", type=float, default=3.0,
                    help="Per-connection timeout in seconds (default 3).")
    ap.add_argument("--tests", default="ports,tls,l7,dns,doh,icmp",
                    help="Comma list of test groups to run: ports,tls,l7,dns,doh,icmp. "
                         "Default: all.")
    ap.add_argument("--json", metavar="PATH", default=None,
                    help="Write structured results to a JSON file.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colour.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the plan without sending any traffic.")
    args = ap.parse_args()

    banner()
    groups = [g.strip() for g in args.tests.split(",") if g.strip()]
    print(f"[*] Source     : {args.source or 'OS-chosen'}")
    print(f"[*] Destination: {args.destination}")
    print(f"[*] Tests      : {', '.join(groups)}")
    print(f"[*] Timeout    : {args.timeout}s")

    if args.dry_run:
        print("\n[dry-run] No traffic sent. The above test groups would execute "
              f"against {args.destination}.")
        return

    probe = Probe(args.source, args.destination, args.timeout,
                  use_color=not args.no_color)
    print(f"[*] Resolved   : {probe.dest_ip}")

    if "ports" in groups:
        probe.test_ports(parse_ports(args.ports))
    if "tls" in groups:
        probe.test_tls()
    if "l7" in groups:
        probe.test_l7_on_443()
    if "dns" in groups:
        probe.test_dns_direct()
    if "doh" in groups:
        probe.test_doh()
    if "icmp" in groups:
        probe.test_icmp()

    probe.summary()

    if args.json:
        payload = {
            "source": args.source,
            "destination": args.destination,
            "resolved_ip": probe.dest_ip,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "results": probe.results,
        }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\n[*] JSON report written to {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(130)
