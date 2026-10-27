"""LDAP null/anonymous bind. Discloses AD naming context without any
credentials — matches the manual test script's ldapsearch check exactly.

ldapsearch is PREFERRED but not required: when it's absent the module falls back to
the ldap3 Python library (a tested LDAP client, already a dependency of the AD
modules) for the same anonymous-bind + root-DSE namingContexts read, so the test
still runs without the CLI instead of PREREQ-MISSING."""
import shutil

META = {
    "id": "ldap_null_bind",
    "name": "LDAP Null Bind",
    "category": "AD Exploitation",
    "test_type": "va",
    "control": "Anonymous LDAP bind hardening",
    "fix": "Server",
    "mitre": ['T1087.002'],
    "cwe": ['CWE-306'],
    "tactic": 'Discovery',
    "requires": [],          # ldapsearch PREFERRED; ldap3 Python fallback otherwise
    "ports": [("tcp", 389)],
    "port_customizable": True,
    # Anchor to the RESPONSE attribute line (LDIF: "namingContexts: DC=..."),
    # not the bare word — core prepends a "# command: ldapsearch ... namingContexts"
    # header to every log, and an unanchored /namingContexts/ matched THAT,
    # reporting SUCCESS on every run (even tool-not-found / refused). ^...:
    # under re.MULTILINE matches only a real reply line, not the echoed command.
    "success_regex": r"^namingContexts:",
    # reset tokens: a bare "Connection reset by peer" from the ldapsearch CLI that
    # isn't wrapped in "Can't contact LDAP server" would otherwise fall to NO-RESULT;
    # a reset on the bind with 389 open is the target/boundary refusing it = BLOCKED.
    "blocked_regex": r"timed out|Can't contact LDAP|Connection refused|Connection reset|reset by peer",
}


def _ldap3_probe(target, port, ctx):
    """Anonymous bind + root-DSE namingContexts read via ldap3 (ldapsearch fallback).
    Emits LDIF-style 'namingContexts: <DN>' lines the success_regex matches, or a
    connection-error line the blocked/refused regex + recon classify."""
    out = [f"# (python ldap3 fallback — ldapsearch not installed) ldap://{target}:{port}"]
    try:
        from ldap3 import Server, Connection, ANONYMOUS, BASE
    except Exception:
        return ("# ldap_null_bind vs %s\n[PREREQ-MISSING] neither ldapsearch nor the ldap3 "
                "Python library is available (apt install ldap-utils, or pip install ldap3)."
                % target)
    conn = None
    try:
        server = Server(target, port=port, connect_timeout=8)
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=False, receive_timeout=10)
        if not conn.bind():
            out.append("anonymous bind rejected: %s" % (conn.result or {}).get("description", "see result"))
            return "\n".join(out)
        conn.search(search_base="", search_filter="(objectClass=*)",
                    search_scope=BASE, attributes=["namingContexts"])
        ncs = []
        for e in (conn.response or []):
            for v in (e.get("attributes", {}) or {}).get("namingContexts", []) or []:
                ncs.append(str(v))
        if ncs:
            for dn in ncs:
                out.append("namingContexts: %s" % dn)   # matches success_regex ^namingContexts:
        else:
            out.append("anonymous bind OK but no namingContexts returned (root-DSE read restricted)")
    except Exception as e:
        # ldap3 raises LDAPSocket*/LDAPException on connect failures — surface a line the
        # blocked/refused regex (or recon) classifies (timed out / refused / can't contact).
        msg = str(e) or e.__class__.__name__
        low = msg.lower()
        if "refused" in low:
            out.append("Connection refused")
        elif "time" in low:
            out.append("timed out")
        else:
            out.append("Can't contact LDAP server (%s: %s)" % (e.__class__.__name__, msg))
    finally:
        try:
            if conn is not None:
                conn.unbind()
        except Exception:
            pass
    return "\n".join(out)


def run(target, ctx):
    port = ctx.get_port("ldap_null_bind", 389)   # overridable per-attack (GUI/env)
    if shutil.which("ldapsearch"):
        # -o nettimeout / -l bound the connect+search so a FILTERED 389 fails fast with
        # ldapsearch's own "Can't contact LDAP server" / "Timed out" line (which the
        # blocked/refused regex + recon then classify) instead of hanging until the
        # engine watchdog kills it with empty output (-> a mute NO-RESULT on a port the
        # boundary is actually dropping).
        return ctx.run_cmd(
            f'ldapsearch -x -o nettimeout=8 -l 10 -H ldap://{{target}}:{port} '
            f'-b "" -s base namingContexts', target)
    return _ldap3_probe(target, port, ctx)
