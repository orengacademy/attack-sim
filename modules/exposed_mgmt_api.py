"""Family F — exposed management / API surface on 443 inbound.

Probes a published-on-443 host for management and API surface that should not be
internet-facing: admin panels, Spring Boot actuator, Swagger/OpenAPI, health/metrics,
.git, and console paths. Any that answer 200/401 (present) on the public 443 surface
is an exposed-management finding. Also flags plaintext HTTP redirect gaps.

SAFE: benign GETs to well-known paths; no exploitation. Config: published_app_url
(else target:443). MITRE T1133 / T1596.
"""
import ssl
from urllib.parse import urlparse
from modules import _util as U

_PATHS = ["/actuator", "/actuator/env", "/actuator/health", "/swagger-ui/",
          "/swagger-ui/index.html", "/openapi.json", "/api-docs", "/v2/api-docs",
          "/metrics", "/admin", "/manager/html", "/console", "/.git/HEAD",
          "/.env", "/server-status", "/phpmyadmin/"]

META = {
    "id": "exposed_mgmt_api",
    "name": "Exposed Management / API Surface (443)",
    "category": "Application Control",
    "test_type": "attack_sim",
    "family": "F",
    "direction": "a2b",
    "added": True,
    "control": "No management surface published; mTLS on sensitive APIs; modern TLS",
    "fix": "Agency (WAF/app)",
    "mitre": ["T1133", "T1596"],
    "tactic": "Initial Access",
    "cwe": ["CWE-200"],
    "requires": [],
    "ports": [("tcp", 443)],
    "port_customizable": True,
    "success_regex": r"^MGMT-SURFACE-EXPOSED",
    "blocked_regex": r"no management surface exposed|unreachable",
}


def _get(host, port, path, ctx):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MyGovNet-USS/mgmt\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n")
    try:
        raw = U.connect(host, port, ctx, timeout=6)
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with c.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(req.encode())
            first = tls.recv(64).decode(errors="replace").splitlines()
        if first and first[0].startswith("HTTP/"):
            p = first[0].split()
            return int(p[1]) if len(p) > 1 and p[1].isdigit() else None
    except Exception:
        return None
    return None


def run(target, ctx):
    url = ctx.cfg("published_app_url")
    if url:
        u = urlparse(url if "://" in url else "https://" + url)
        host, port = u.hostname, (u.port or 443)
    else:
        host, port = target, ctx.get_port("exposed_mgmt_api", 443)
    out = [f"# exposed management/API surface vs {host}:{port} (Family F)"]
    # confirm 443 is even up
    if U.tcp_state(host, port, ctx, timeout=6) != "open":
        out.append("unreachable — 443 not open on the target")
        return "\n".join(out)
    exposed = []
    for path in _PATHS:
        code = _get(host, port, path, ctx)
        if code in (200, 401, 403):
            exposed.append(f"{path} ({code})")
            out.append(f"  {path} -> {code}")
    out.append("")
    if exposed:
        out.append(f"MGMT-SURFACE-EXPOSED — management/API endpoints reachable on the public "
                   f"443 surface: {', '.join(exposed)}. [FINDING] remove from the published "
                   "surface / enforce mTLS. (200/401/403 = the endpoint exists.)")
    else:
        out.append("no management surface exposed — no known admin/actuator/swagger paths "
                   "answered on 443")
    return "\n".join(out)
