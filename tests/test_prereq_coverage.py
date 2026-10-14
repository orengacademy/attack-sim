"""Regression guard: every external tool a module declares in META['requires']
must have an entry in core.INSTALL_HINTS, so preflight can name the package to
install (instead of "no known package mapping — install it manually") and
bootstrap.py can provision it. This is what keeps prerequisite handling complete
as new modules are added.

Pure-stdlib / offline (no network, no install, just metadata)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core      # noqa: E402
import loader    # noqa: E402


class TestPrereqCoverage(unittest.TestCase):
    def test_every_required_tool_is_mapped(self):
        mapped = set(core.INSTALL_HINTS)
        missing = {}
        for mod in loader.discover():
            for tool in (mod.META.get("requires") or []):
                if tool not in mapped:
                    missing.setdefault(tool, []).append(mod.META["id"])
        self.assertFalse(
            missing,
            "these required tools have no core.INSTALL_HINTS entry (preflight can't name "
            "a package / bootstrap can't install them): "
            + "; ".join(f"{t} (needed by {', '.join(ids)})" for t, ids in sorted(missing.items())))

    def test_install_hints_entries_have_apt(self):
        # Kali/Debian (apt) is the supported attacker platform (bootstrap.py is apt);
        # every hint must at least carry an apt package (or a pip/note fallback).
        for tool, h in core.INSTALL_HINTS.items():
            self.assertTrue(
                h.get("apt") or h.get("pip") or h.get("note"),
                f"INSTALL_HINTS['{tool}'] has no apt/pip/note install path")


if __name__ == "__main__":
    unittest.main()
