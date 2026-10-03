#!/usr/bin/env python3
"""
loader.py — auto-discovers attack modules.

Every .py file in modules/ that exposes a META dict and a run(target, ctx)
function is picked up automatically. Drop a new file in modules/ and it
appears in the GUI on next launch — no registration needed.

META must contain at least: id, name, category. Recommended:
control, fix, success_regex, blocked_regex.
"""

import os
import importlib

MODULES_PKG = "modules"


def discover():
    """Return the list of valid attack modules, sorted by (category, name)."""
    here = os.path.dirname(os.path.abspath(__file__))
    mdir = os.path.join(here, MODULES_PKG)
    found = []
    for fn in sorted(os.listdir(mdir)):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        name = fn[:-3]
        try:
            mod = importlib.import_module(f"{MODULES_PKG}.{name}")
        except Exception as e:
            print(f"[loader] skipped {fn}: {e}")
            continue
        if hasattr(mod, "META") and hasattr(mod, "run") and callable(mod.run):
            meta = mod.META
            if "id" in meta and "name" in meta and "category" in meta:
                found.append(mod)
            else:
                print(f"[loader] {fn}: META missing id/name/category — skipped")
        else:
            print(f"[loader] {fn}: no META/run — skipped")
    # Optional META["order"] lets a module jump the default (category, name)
    # alphabetical placement (e.g. putting Server Exploitation mid-batch, with
    # DNS-over-HTTPS Bypass right after it, ahead of the run_last DoS/brute
    # tail). Default 0 == untouched modules keep today's alphabetical order.
    found.sort(key=lambda m: (m.META.get("order", 0), m.META["category"], m.META["name"]))
    return found


def grouped():
    """Return an ordered dict: category -> [modules]."""
    out = {}
    for m in discover():
        out.setdefault(m.META["category"], []).append(m)
    return out
