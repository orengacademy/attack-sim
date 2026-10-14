"""Fallback coverage: each tool-wrapper original module must (a) have the external tool
DEMOTED from `requires` to preferred (so run() executes and the Python fallback can
engage instead of PREREQ-MISSING), and (b) carry a Python fallback. Plus pins the one
hand-rolled wire protocol (snmp_brute's SNMP GET) since it isn't library-backed.

Pure-stdlib / offline."""
import importlib.util
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import core  # noqa: E402


def _load(name):
    sys.modules.setdefault("core", core)
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "modules", f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


class TestToolDemotedToPreferred(unittest.TestCase):
    # module -> tool that must NOT be a hard requirement anymore (so the fallback runs)
    CASES = {
        "ftp_anonymous": "curl", "snmp_brute": "snmpbulkwalk", "ldap_null_bind": "ldapsearch",
        "apache_41773": "curl", "doh_bypass": "curl", "log4shell": "curl", "ssh_brute": "hydra",
    }

    def test_tool_not_in_requires(self):
        for mod, tool in self.CASES.items():
            m = _load(mod)
            self.assertNotIn(tool, m.META.get("requires") or [],
                             f"{mod}: {tool} still in requires -> PREREQ-MISSING would skip the fallback")


class TestSnmpBerFallback(unittest.TestCase):
    def setUp(self):
        self.m = _load("snmp_brute")

    def test_get_packet_well_formed(self):
        pkt = self.m._snmp_get_packet("public", 0x11223344)
        self.assertEqual(pkt[0], 0x30)                  # SEQUENCE
        self.assertIn(b"public", pkt)                   # community
        self.assertIn(self.m._SYSDESCR_OID, pkt)        # sysDescr.0 OID

    def test_parse_string_value_matches_success_regex(self):
        m = self.m
        vb = m._tlv(0x30, m._tlv(0x06, m._SYSDESCR_OID) + m._tlv(0x04, b"Linux testhost 6.1"))
        pdu = m._tlv(0xA2, m._tlv(0x02, b"\x11\x22\x33\x44") + m._tlv(0x02, b"\x00")
                     + m._tlv(0x02, b"\x00") + m._tlv(0x30, vb))
        resp = m._tlv(0x30, m._tlv(0x02, b"\x01") + m._tlv(0x04, b"public") + pdu)
        line = m._snmp_value(resp)
        self.assertEqual(line, "= STRING: Linux testhost 6.1")
        self.assertTrue(re.search(m.META["success_regex"], "SNMPv2-MIB::sysDescr.0 " + line))

    def test_null_value_is_not_success(self):
        m = self.m
        vb = m._tlv(0x30, m._tlv(0x06, m._SYSDESCR_OID) + m._tlv(0x05, b""))
        pdu = m._tlv(0xA2, m._tlv(0x02, b"\x00") * 3 + m._tlv(0x30, vb))
        resp = m._tlv(0x30, m._tlv(0x02, b"\x01") + m._tlv(0x04, b"public") + pdu)
        self.assertIsNone(m._snmp_value(resp))


if __name__ == "__main__":
    unittest.main()
