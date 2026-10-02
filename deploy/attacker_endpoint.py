#!/usr/bin/env python3
"""attacker_endpoint.py — stand up the "attacker infra" the egress / C2 / exfil
modules aim at, so they have a REAL endpoint to reach and score SUCCESS instead of
[SKIP]. Pure stdlib; run it on your VPS (or this vuln box, which doubles as the
sink in a closed lab), then point config.json at it:

    python3 deploy/attacker_endpoint.py --http 8000 --tcp 443,9001 --udp 5353,443

    # config.json on the harness host:
    #   "canary_url":        "http://<endpoint-ip>:8000/canary",
    #   "published_app_url": "http://<endpoint-ip>:8000/",
    #   "attacker_vps":      "<endpoint-ip>"

It LOGS every hit (who / method / path / size) to stdout and --log, and answers
200 / "SINK-OK" — benign, nothing is executed. This covers the HTTP/TCP/UDP-sink
modules (canary POST, beacon, DLP exfil, reverse/proxy egress, QUIC/UDP, tunnel
brokers). The DNS-authoritative modules (dns_tunnel / covert_channel / NRD) still
need a real domain delegated to a resolver you run — a sink can't fake that.

Optional HTTPS: pass --cert FILE --key FILE to serve the canary over TLS too.
Authorised-engagement use only.
"""
import argparse
import datetime
import http.server
import socket
import ssl
import sys
import threading

_LOG = None


def _ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _emit(line):
    print(line, flush=True)
    if _LOG:
        try:
            with open(_LOG, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass


class _Canary(http.server.BaseHTTPRequestHandler):
    server_version = "nginx"   # look mundane

    def _hit(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        _emit(f"[{_ts()}] HTTP {self.command} {self.path} from {self.client_address[0]} "
              f"ua='{self.headers.get('User-Agent', '')}' len={len(body)}"
              + (f" body={body[:120]!r}" if body else ""))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        try:
            self.wfile.write(b"CANARY-OK\n")
        except Exception:
            pass

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _hit

    def log_message(self, *a):   # silence the default per-request stderr spam
        pass


def _serve_http(port, cert, key):
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), _Canary)
    scheme = "http"
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    _emit(f"[{_ts()}] canary listening on {scheme}://0.0.0.0:{port}/ (logs every request, 200 CANARY-OK)")
    httpd.serve_forever()


def _serve_tcp(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    _emit(f"[{_ts()}] TCP sink listening on 0.0.0.0:{port}")
    while True:
        try:
            c, a = s.accept()
            threading.Thread(target=_tcp_conn, args=(c, a, port), daemon=True).start()
        except Exception:
            continue


def _tcp_conn(c, a, port):
    try:
        c.settimeout(5)
        data = b""
        try:
            data = c.recv(4096)
        except Exception:
            pass
        _emit(f"[{_ts()}] TCP :{port} connect from {a[0]}:{a[1]}  {len(data)}B"
              + (f" {data[:80]!r}" if data else ""))
        try:
            c.sendall(b"SINK-OK\n")
        except Exception:
            pass
    finally:
        try:
            c.close()
        except Exception:
            pass


def _serve_udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    _emit(f"[{_ts()}] UDP sink listening on 0.0.0.0:{port}")
    while True:
        try:
            data, a = s.recvfrom(8192)
            _emit(f"[{_ts()}] UDP :{port} {len(data)}B from {a[0]}:{a[1]}")
            try:
                s.sendto(b"SINK-OK", a)
            except Exception:
                pass
        except Exception:
            continue


def _ports(spec):
    out = []
    for p in (spec or "").split(","):
        p = p.strip()
        if p.isdigit():
            out.append(int(p))
    return out


def main():
    global _LOG
    ap = argparse.ArgumentParser(description="Attacker-infra sink for the egress/C2/exfil modules.")
    ap.add_argument("--http", type=int, help="HTTP(S) canary port (logs + 200)")
    ap.add_argument("--tcp", help="comma list of TCP sink ports (e.g. 443,9001)")
    ap.add_argument("--udp", help="comma list of UDP sink ports (e.g. 5353,443)")
    ap.add_argument("--cert", help="TLS cert file (serve the canary over HTTPS)")
    ap.add_argument("--key", help="TLS key file")
    ap.add_argument("--log", help="also append every hit to this file")
    args = ap.parse_args()
    _LOG = args.log
    if not (args.http or args.tcp or args.udp):
        ap.error("give at least one of --http / --tcp / --udp")

    threads = []
    if args.http:
        threads.append(threading.Thread(target=_serve_http, args=(args.http, args.cert, args.key), daemon=True))
    for p in _ports(args.tcp):
        threads.append(threading.Thread(target=_serve_tcp, args=(p,), daemon=True))
    for p in _ports(args.udp):
        threads.append(threading.Thread(target=_serve_udp, args=(p,), daemon=True))
    for t in threads:
        t.start()
    _emit(f"[{_ts()}] attacker endpoint up ({len(threads)} listener(s)) — Ctrl-C to stop")
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        _emit(f"[{_ts()}] shutting down")
        return 0


if __name__ == "__main__":
    sys.exit(main())
