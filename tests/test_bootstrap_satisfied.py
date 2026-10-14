"""Regression: bootstrap must treat a package as satisfied when the binary it
provides is on PATH, even if dpkg doesn't know the exact package name. This is the
transitional/renamed-package case (Kali: `dnsutils` -> `bind9-dnsutils`; `dig` is
present but `dpkg -s dnsutils` fails), which was reported as a FALSE "[FAILED]
1 package still missing: dnsutils".

Pure-stdlib / offline: apt_installed and shutil.which are stubbed, nothing runs."""
import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_bootstrap():
    spec = importlib.util.spec_from_file_location("bootstrap", os.path.join(ROOT, "bootstrap.py"))
    b = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = b
    spec.loader.exec_module(b)
    return b


class TestBootstrapSatisfied(unittest.TestCase):
    def setUp(self):
        self.b = _load_bootstrap()
        self._real_which = self.b.shutil.which

    def tearDown(self):
        self.b.shutil.which = self._real_which

    def test_transitional_package_satisfied_by_binary(self):
        # dpkg doesn't know 'dnsutils', but 'dig' is on PATH -> satisfied
        self.b.apt_installed = lambda pkg: False
        self.b.shutil.which = lambda x: "/usr/bin/dig" if x == "dig" else None
        self.assertTrue(self.b._satisfied("dnsutils"),
                        "dnsutils must be satisfied when dig is on PATH (bind9-dnsutils)")

    def test_missing_when_neither_pkg_nor_binary(self):
        self.b.apt_installed = lambda pkg: False
        self.b.shutil.which = lambda x: None
        self.assertFalse(self.b._satisfied("dnsutils"))
        self.assertFalse(self.b._satisfied("nmap"))

    def test_dpkg_installed_is_satisfied(self):
        self.b.apt_installed = lambda pkg: True
        self.b.shutil.which = lambda x: None
        self.assertTrue(self.b._satisfied("curl"))

    def test_alias_installed_is_satisfied(self):
        # impacket-scripts absent, but its alias python3-impacket is dpkg-installed
        self.b.shutil.which = lambda x: None
        self.b.apt_installed = lambda pkg: pkg == "python3-impacket"
        self.assertTrue(self.b._satisfied("impacket-scripts"))


if __name__ == "__main__":
    unittest.main()
