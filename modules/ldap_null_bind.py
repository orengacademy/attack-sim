"""LDAP null/anonymous bind. Discloses AD naming context without any
credentials — matches the manual test script's ldapsearch check exactly."""
META = {
    "id": "ldap_null_bind",
    "name": "LDAP Null Bind",
    "category": "AD Exploitation",
    "control": "Anonymous LDAP bind hardening",
    "fix": "Server",
    "requires": ["ldapsearch"],
    # Anchor to the RESPONSE attribute line (LDIF: "namingContexts: DC=..."),
    # not the bare word — core prepends a "# command: ldapsearch ... namingContexts"
    # header to every log, and an unanchored /namingContexts/ matched THAT,
    # reporting SUCCESS on every run (even tool-not-found / refused). ^...:
    # under re.MULTILINE matches only a real reply line, not the echoed command.
    "success_regex": r"^namingContexts:",
    "blocked_regex": r"timed out|Can't contact LDAP|Connection refused",
}


def run(target, ctx):
    return ctx.run_cmd(
        'ldapsearch -x -H ldap://{target} -b "" -s base namingContexts', target)
