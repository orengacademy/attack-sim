#!/usr/bin/env python3
"""Generate docs/MODULES.md — a per-module reference (what it tests, why, what it
needs, and how to block/prevent) straight from each module's META + docstring, so
it stays accurate and can be regenerated after any module change:

    python3 additional/gen_module_docs.py        # writes docs/MODULES.md

Pure stdlib. The `control` META field is the remediation (how to prevent) and
`fix` is the owner (SD-WAN / Server / Agency); the docstring's first paragraph is
"what it tests / why". Nothing is hand-maintained here.
"""
import inspect
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import loader  # noqa: E402

_VERDICT = ("**Reading the verdict:** SUCCESS = the attack reached/worked (a finding — the "
            "control did NOT stop it); BLOCKED = a control stopped it (green); DETECTED = it "
            "passed but the SOC/appliance alerted; NO-SERVICE = the port/service wasn't there; "
            "SKIPPED = needs config/creds it didn't have; NO-RESULT = inconclusive (read the raw log).")


def _first_para(doc):
    doc = (doc or "").strip()
    if not doc:
        return "_(no description)_"
    para = re.split(r"\n\s*\n", doc)[0]
    return re.sub(r"\s+", " ", para).strip()


def _ports(meta):
    ps = meta.get("ports") or []
    if not ps:
        return "— (no target port; egress / ICMP)"
    return ", ".join(f"{p}/{pr}" if p is not None else pr for (pr, p) in ps)


def _needs(m):
    meta = m.META
    bits = []
    req = meta.get("requires") or []
    if req:
        bits.append("tools: " + ", ".join(req))
    if meta.get("requires_py"):
        bits.append("python: " + ", ".join(meta["requires_py"]))
    if meta.get("needs_root"):
        bits.append("**root**")
    if meta.get("active"):
        bits.append("**--active** (live establishment)")
    try:
        src = inspect.getsource(m)
    except Exception:
        src = ""
    cfg = sorted(set(re.findall(r'ctx\.cfg\(\s*["\']([a-z_]+)["\']', src)))
    if cfg:
        bits.append("config.json: " + ", ".join(cfg))
    mid = meta["id"]
    if any(t in mid for t in ("dcsync", "psexec", "wmiexec", "kerber", "nopac", "sama", "petit")):
        bits.append("DC creds")
    if mid == "ssh_brute":
        bits.append("SSH creds")
    return "; ".join(bits) or "nothing (just a reachable target)"


def main():
    mods = sorted(loader.discover(), key=lambda x: (x.META.get("category", ""),
                                                    not (not x.META.get("added")), x.META["id"]))
    bycat = {}
    for m in mods:
        bycat.setdefault(m.META.get("category", "Other"), []).append(m)

    out = []
    out.append("# Module reference — what each attack tests & how to block it\n")
    out.append("> Auto-generated from each module's `META` + docstring by "
               "`additional/gen_module_docs.py` — regenerate after changing a module; don't "
               "hand-edit. Tags: `[original]` = in the default 11-module set, `[added]` = opt-in.\n")
    out.append(_VERDICT + "\n")
    out.append(f"**{len(mods)} modules** across {len(bycat)} categories. "
               "`control` = how to prevent it; `fix` = who owns the fix "
               "(SD-WAN / Server / Agency).\n")
    # index
    out.append("## Contents")
    for cat in sorted(bycat):
        out.append(f"- **{cat}** ({len(bycat[cat])})")
    out.append("")

    for cat in sorted(bycat):
        out.append(f"\n## {cat}\n")
        for m in bycat[cat]:
            meta = m.META
            tag = "original" if not meta.get("added") else "added"
            ids = []
            if meta.get("mitre"):
                ids.append("MITRE " + ", ".join(meta["mitre"]))
            if meta.get("cwe"):
                ids.append(", ".join(meta["cwe"]))
            if meta.get("cve"):
                ids.append(meta["cve"])
            scope = meta.get("test_type", "")
            if meta.get("family"):
                scope += f"/{meta['family']}"
            out.append(f"### {meta['name']}  `{meta['id']}`  _[{tag}]_")
            out.append("")
            out.append(f"- **Scope:** {scope} · direction {meta.get('direction', 'a2b')} · "
                       f"ports {_ports(meta)}" + (f" · {' · '.join(ids)}" if ids else ""))
            out.append(f"- **What it tests / why:** {_first_para(inspect.getdoc(m))}")
            out.append(f"- **Control it validates (how to PREVENT / BLOCK):** {meta.get('control', '—')}")
            out.append(f"- **Fix (owner / remediation):** {meta.get('fix', '—')}")
            out.append(f"- **Needs to run:** {_needs(m)}")
            out.append("")

    docs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
    os.makedirs(docs_dir, exist_ok=True)
    path = os.path.join(docs_dir, "MODULES.md")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"[*] wrote {path} ({len(mods)} modules, {len(bycat)} categories)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
