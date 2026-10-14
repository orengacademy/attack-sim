"""LDAP null/anonymous bind. Discloses AD naming context without any
credentials — matches the manual test script's ldapsearch check exactly."""
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
    "requires": ["ldapsearch"],
    "ports": [("tcp", 389)],
    "port_customizable": True,
    # Anchor to the RESPONSE attribute line (LDIF: "namingContexts: DC=..."),
    # not the bare word — core prepends a "# command: ldapsearch ... namingContexts"
    # header to every log, and an unanchored /namingContexts/ matched THAT,
    # reporting SUCCESS on every run (even tool-not-found / refused). ^...:
    # under re.MULTILINE matches only a real reply line, not the echoed command.
    "success_regex": r"^namingContexts:",
    "blocked_regex": r"timed out|Can't contact LDAP|Connection refused",
}


def run(target, ctx):
    port = ctx.get_port("ldap_null_bind", 389)   # overridable per-attack (GUI/env)
    # -o nettimeout / -l bound the connect+search so a FILTERED 389 fails fast with
    # ldapsearch's own "Can't contact LDAP server" / "Timed out" line (which the
    # blocked/refused regex + recon then classify) instead of hanging until the
    # engine watchdog kills it with empty output (-> a mute NO-RESULT on a port the
    # boundary is actually dropping).
    return ctx.run_cmd(
        f'ldapsearch -x -o nettimeout=8 -l 10 -H ldap://{{target}}:{port} '
        f'-b "" -s base namingContexts', target)
