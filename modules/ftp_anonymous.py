"""FTP anonymous login check. Matches the manual test script's curl test,
with -v added so a real FTP "230 Login successful" is visible even when
the directory listing itself is empty (empty stdout would otherwise look
identical to a rejected login).

curl is PREFERRED but not required: when it's absent the module falls back to a
pure-stdlib ftplib probe (same anonymous-login check), so the test still runs on a
box without curl instead of PREREQ-MISSING."""
import re
import shutil

META = {
    "id": "ftp_anonymous",
    "name": "FTP Anonymous Login",
    "category": "Network Exploitation",
    "test_type": "va",
    "control": "Anonymous access hardening",
    "fix": "Server",
    "mitre": ['T1078.001'],
    "cwe": ['CWE-306'],
    "tactic": 'Initial Access',
    "requires": [],          # curl PREFERRED; pure-stdlib ftplib fallback otherwise
    "ports": [("tcp", 21)],
    "port_customizable": True,
    "success_regex": r"230 Login successful|230 User logged in|230 Anonymous",
    # Added the mid-session RESET signatures: an IPS/WAF (e.g. Sangfor's FTP-anonymous
    # signature) typically lets the TCP connect + 220 banner through, then RESETS the
    # session the instant it sees `USER anonymous` -> curl prints "Recv failure:
    # Connection reset by peer". That is the control working (BLOCKED), but it used to
    # match nothing here and fell through to NO-RESULT. ^FTP-BLOCKED is the module's
    # own explicit marker (below).
    "blocked_regex": (r"530|Login incorrect|Access denied|timed out|Connection refused|"
                      r"Connection reset|reset by peer|Recv failure|^FTP-BLOCKED"),
}


def _ftplib_probe(target, port, ctx):
    """Pure-stdlib anonymous-login probe (curl fallback). Emits FTP-style lines the
    verdict regex already understands: '220 ...' banner, then '230 ...' on accepted
    anonymous login or '530 ...' when it's rejected; a reset/timeout maps to the
    blocked/no-service signatures."""
    import ftplib
    out = [f"# (python ftplib fallback — curl not installed) ftp://{target}:{port}/"]
    src = (getattr(ctx, "source_ip", None) or "")
    src_addr = (src, 0) if src else None
    ftp = ftplib.FTP()
    try:
        ftp.connect(target, port, timeout=8, source_address=src_addr)
        out.append((ftp.getwelcome() or "220 (no banner)").strip())
        resp = ftp.login("anonymous", "anonymous@example.com")   # 230 on success, raises otherwise
        out.append(resp.strip())                                  # e.g. "230 Login successful."
    except ftplib.error_perm as e:
        out.append(str(e).strip() or "530 Login incorrect")       # e.g. "530 Login incorrect."
    except Exception as e:                                         # timeout/reset/refused/proto
        out.append(f"Connection error: {e.__class__.__name__}: {e}")
    finally:
        try:
            ftp.close()
        except Exception:
            pass
    return "\n".join(out)


def run(target, ctx):
    port = ctx.get_port("ftp_anonymous", 21)   # overridable per-attack (GUI/env)
    if shutil.which("curl"):
        raw = ctx.run_cmd(
            f'curl -s -v -m8 "ftp://anonymous:anonymous@{{target}}:{port}/"', target)
    else:
        raw = _ftplib_probe(target, port, ctx)
    # 230 = anonymous login ACCEPTED (the finding) — success_regex decides; leave as-is.
    # Match the real 230 login phrases (not a bare "230", which could appear incidentally
    # in curl's verbose output — a byte count, port, etc. — and wrongly skip the
    # mid-session-reset BLOCKED detection below).
    if re.search(r"230 (Login successful|User logged in|Anonymous)", raw, re.I):
        return raw
    # Banner (220) received but the session was RESET / torn down before a 230 success
    # => the anonymous login was refused MID-EXCHANGE. On this lab that's the appliance's
    # FTP-anonymous IPS resetting `USER anonymous` (or host hardening). Make it an
    # explicit BLOCKED so a reset isn't a mute NO-RESULT. (A plain closed/refused port
    # with no banner stays NO-SERVICE via recon — this only fires once the service
    # answered, i.e. it IS there and the login specifically was cut.)
    if re.search(r"\b220\b", raw) and re.search(
            r"reset by peer|Recv failure|Connection reset|\b5\d\d\b|Login incorrect|Access denied",
            raw, re.I):
        raw += ("\n\nFTP-BLOCKED: the FTP banner (220) came back but the anonymous login was "
                "RESET/denied before any 230 success — anonymous access is blocked (server "
                "hardening, or the appliance's FTP-anonymous IPS reset the `USER anonymous` "
                "session). Control works.")
    return raw
