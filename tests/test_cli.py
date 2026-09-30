#!/usr/bin/env python3
"""Tests for the headless CLI selection/port parsing (no GUI/display needed)."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cli  # noqa: E402


def mod(mid, added=False):
    m = types.SimpleNamespace()
    m.META = {"id": mid, "name": mid, "category": "T", "added": added}
    return m


class Args:
    only = None; original = False; added = False


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
