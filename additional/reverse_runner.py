#!/usr/bin/env python3
"""
reverse_runner.py — SELF-CONTAINED reverse-egress probe for a data-centre foothold.

Drop this ONE file on a KVDC/IPDC (or cloud) server you have a foothold on and run
it to test the B->A / B->out direction — server-initiated egress — which the main
harness can't test from the tester side. No dependencies beyond the Python stdlib,
no repo needed. Non-destructive: it connects / sends tiny probes, nothing else.

    python3 reverse_runner.py                       # default checks, to public infra
    python3 reverse_runner.py --vps 203.0.113.9     # to your redirector
    python3 reverse_runner.py --source 10.20.0.5    # bind to the DC interface/VRF
    python3 reverse_runner.py --json                 # machine-readable

A reachable egress path from a server VLAN = a finding: DC hosts should be
default-denied outbound except an explicit allow-list. Authorised use only.
MITRE T1571 / T1090 / T1048 / T1071.004.
"""
import argparse
import json
import socket
import ssl
import struct
import sys

TIMEOUT = 6

# server-initiated egress a reverse shell / beacon / exfil would attempt
EGRESS_PORTS = [443, 80, 53, 22, 8080, 8443, 4444, 9001, 853]
PUBLIC = ["1.1.1.1", "8.8.8.8"]
TUNNEL_BROKERS = [("cloudflared", "api.trycloudflare.com"),
                  ("ngrok", "connect.ngrok-agent.com"),
                  ("devtunnels", "global.rel.tunnels.api.visualstudio.com")]
SAAS = [("github", "api.github.com"), ("ms-graph", "graph.microsoft.com"),
        ("slack", "slack.com"), ("telegram", "api.telegram.org")]
DOH = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]


def _src(source):
    return (source, 0) if source else None


def tcp(host, port, source):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT, source_address=_src(source)):
            return "open"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except ConnectionRefusedError:
        return "refused"
    except socket.gaierror:
        return "unresolved"
    except OSError:
        return "unreachable"


def tls(host, port, source):
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT, source_address=_src(source)) as raw:
            with c.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLError:
        return True          # egress reached the peer (TLS-level error still = out)
    except OSError:
        return False


def udp(host, port, source, payload=b"\x00"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        if source:
            try:
                s.bind((source, 0))
            except OSError:
                pass
        s.sendto(payload, (host, port))
        try:
            s.recvfrom(1024)
            return "reply"
        except socket.timeout:
            return "sent (no reply)"
    except OSError:
        return "blocked"
    finally:
        s.close()


def dns_external(resolver, source):
    tid = 0x1234
    q = (struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) +
         b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        if source:
            try:
                s.bind((source, 0))
            except OSError:
                pass
        s.sendto(q, (resolver, 53))
        s.recvfrom(1024)
        return True
    except OSError:
        return False
    finally:
        s.close()


def doh(url, source):
    # stdlib urllib; source-binding urllib is awkward, so this reflects the host's
    # default route (note it in the report if you pinned --source).
    import urllib.request
    sep = "&" if "?" in url else "?"
    try:
        req = urllib.request.Request(url + sep + "name=example.com&type=A",
                                     headers={"accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(2048).decode(errors="replace")
            return '"Answer"' in body or '"Status"' in body or '"data"' in body
    except Exception:
        return False


def run(vps, source):
    findings = []
    report = {"direction": "b2a (server-initiated)", "source": source or "default route",
              "tests": {}}

    # 1) reverse egress ports (to VPS if given, else public)
    dests = [vps] if vps else PUBLIC
    ports = {}
    for host in dests:
        for p in EGRESS_PORTS:
            st = tcp(host, p, source)
            ports[f"{host}:{p}"] = st
            if st == "open":
                findings.append(f"server egress open {host}:{p}")
    report["tests"]["reverse_egress_ports"] = ports

    # 2) tunnel-broker reach
    brokers = {}
    for label, host in TUNNEL_BROKERS:
        ok = tls(host, 443, source)
        brokers[label] = "reachable" if ok else "blocked"
        if ok:
            findings.append(f"tunnel broker reachable: {label}")
    report["tests"]["tunnel_brokers"] = brokers

    # 3) LOTS SaaS reach
    saas = {}
    for label, host in SAAS:
        ok = tls(host, 443, source)
        saas[label] = "reachable" if ok else "blocked"
        if ok:
            findings.append(f"SaaS reachable: {label}")
    report["tests"]["lots_saas"] = saas

    # 4) DNS egress
    dns = {"external_53": "open" if dns_external("8.8.8.8", source) else "blocked"}
    if dns["external_53"] == "open":
        findings.append("external DNS (53) egress open")
    for url in DOH:
        ok = doh(url, source)
        dns[url] = "resolved" if ok else "blocked"
        if ok:
            findings.append(f"DoH bypass: {url}")
    report["tests"]["dns"] = dns

    # 5) UDP/443 (QUIC) + 853
    udpr = {}
    for host in dests:
        for p in (443, 853):
            st = udp(host, p, source)
            udpr[f"{host}:{p}/udp"] = st
    report["tests"]["udp"] = udpr

    report["findings"] = findings
    report["verdict"] = ("FINDINGS — server-initiated egress paths open (see findings)"
                         if findings else
                         "OK — no server-initiated egress got out (default-deny holding)")
    return report


def main():
    ap = argparse.ArgumentParser(description="Reverse-egress (B->A) probe for a DC foothold.")
    ap.add_argument("--vps", help="your redirector/VPS to aim egress at (else public IPs)")
    ap.add_argument("--source", help="source IP to bind egress to (the DC interface/VRF)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    rep = run(args.vps, args.source)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"== reverse-egress probe ({rep['direction']}) — source {rep['source']} ==")
        for name, res in rep["tests"].items():
            print(f"\n[{name}]")
            for k, v in res.items():
                print(f"  {k:<40} {v}")
        print("\nFindings:")
        for f in rep["findings"] or ["  (none)"]:
            print(f"  - {f}" if rep["findings"] else f)
        print(f"\nVerdict: {rep['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
