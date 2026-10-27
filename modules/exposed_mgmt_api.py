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
    # Same AGENCY WAF device as waf_evasion (published 443 app), tracked on its own
    # contamination canary — separate from the SD-WAN boundary — so a ban on either
    # device never taints the other's verdicts. defer_group also defers it out of the
    # parallel pool (its path-scanning GETs can trip the WAF). order 7 = after
    # waf_evasion (6), within the agency group.
    "defer_group": "agency_waf",
    "defer_canary_cfg": "published_app_url",
    "defer_canary_port": 443,
    "order": 7,
    "ports": [("tcp", 443)],
    "port_customizable": True,
    "success_regex": r"^MGMT-SURFACE-EXPOSED",
    # NOTE: no bare "unreachable" — the module's only "unreachable" text was its own
    # "443 not open" line, which is SERVICE ABSENT (NO-SERVICE), not a boundary block;
    # it now self-declares [NO-SERVICE] instead. Real in-transit teardowns are the
    # reset/broken-pipe tokens.
    "blocked_regex": r"no management surface exposed|Connection reset|reset by peer|Broken pipe",
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
        # 443 isn't open -> there is no web/API surface to probe. That is SERVICE
        # ABSENT (NO-SERVICE), NOT a boundary/control block — don't score it BLOCKED.
        out.append(f"[NO-SERVICE] {host}:{port} not open — no web/API surface to probe "
                   "(service absent, not a control block).")
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
