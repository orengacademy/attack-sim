"""LDAP null/anonymous bind. Discloses AD naming context without any
credentials — matches the manual test script's ldapsearch check exactly."""
META = {
    "id": "ldap_null_bind",
    "name": "LDAP Null Bind",
    "category": "AD Exploitation",
    "control": "Anonymous LDAP bind hardening",
    "fix": "Server",
    "success_regex": r"namingContexts",
    "blocked_regex": r"timed out|Can't contact LDAP|Connection refused",
}


def run(target, ctx):
    return ctx.run_cmd(
        'ldapsearch -x -H ldap://{target} -b "" -s base namingContexts', target)
