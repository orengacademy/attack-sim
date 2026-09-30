#!/usr/bin/env python3
"""Tests for the headless CLI selection/port parsing (no GUI/display needed)."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cli  # noqa: E402


def mod(mid, added=False, test_type="", family=""):
    m = types.SimpleNamespace()
    m.META = {"id": mid, "name": mid, "category": "T", "added": added,
              "test_type": test_type, "family": family}
    return m


class Args:
    only = None; original = False; added = False
    test_type = None; attack_sim = False; family = None


class TestCliSelect(unittest.TestCase):
    def setUp(self):
        self.mods = [mod("a"), mod("b", added=True), mod("c")]

    def test_all_default(self):
        self.assertEqual(len(cli._select(self.mods, Args())), 3)

    def test_only(self):
        a = Args(); a.only = "a,c"
        self.assertEqual({m.META["id"] for m in cli._select(self.mods, a)}, {"a", "c"})

    def test_original(self):
        a = Args(); a.original = True
        self.assertEqual({m.META["id"] for m in cli._select(self.mods, a)}, {"a", "c"})

    def test_added(self):
        a = Args(); a.added = True
        self.assertEqual({m.META["id"] for m in cli._select(self.mods, a)}, {"b"})


class TestCliScopeFilter(unittest.TestCase):
    def setUp(self):
        self.mods = [mod("t1", test_type="attack_sim", family="A"),
                     mod("t2", test_type="attack_sim", family="B"),
                     mod("p1", test_type="pentest"),
                     mod("d1", test_type="dos")]

    def test_attack_sim_shortcut(self):
        a = Args(); a.attack_sim = True
        self.assertEqual({m.META["id"] for m in cli._select(self.mods, a)}, {"t1", "t2"})

    def test_test_type(self):
        a = Args(); a.test_type = "dos"
        self.assertEqual({m.META["id"] for m in cli._select(self.mods, a)}, {"d1"})

    def test_family(self):
        a = Args(); a.attack_sim = True; a.family = "A"
        self.assertEqual({m.META["id"] for m in cli._select(self.mods, a)}, {"t1"})


class TestCliPorts(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(cli._parse_ports("log4shell=8983, ssh_brute=2222"),
                         {"log4shell": 8983, "ssh_brute": 2222})

    def test_ignores_bad(self):
        self.assertEqual(cli._parse_ports("x=abc, y=443, junk"), {"y": 443})

    def test_empty(self):
        self.assertEqual(cli._parse_ports(""), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
