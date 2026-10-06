"""Lock the shared core.display_ports() helper so the CLI, GUI, web app and evidence
all render a module's ports the SAME way — canonical 'proto/port' format AND the cloud
NAT mapping (tcp/445->4445) applied for a registered cloud target. Offline/stdlib."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402
from modules import _portpatch  # noqa: E402


class TestDisplayPorts(unittest.TestCase):
    def setUp(self):
        self._orig = dict(_portpatch.CUSTOM_PORT_TARGETS)
        _portpatch.CUSTOM_PORT_TARGETS["10.0.0.9"] = {445: 4445, 135: 1135}  # a NAT'd cloud target

    def tearDown(self):
        _portpatch.CUSTOM_PORT_TARGETS.clear()
        _portpatch.CUSTOM_PORT_TARGETS.update(self._orig)

    def test_cloud_nat_is_shown(self):
        meta = {"ports": [("tcp", 445), ("tcp", 135)]}
        self.assertEqual(core.display_ports(meta, "10.0.0.9"), "tcp/445->4445, tcp/135->1135")

    def test_non_cloud_is_plain(self):
        meta = {"ports": [("tcp", 445), ("tcp", 135)]}
        self.assertEqual(core.display_ports(meta, "10.38.98.14"), "tcp/445, tcp/135")

    def test_no_target_is_logical(self):
        self.assertEqual(core.display_ports({"ports": [("tcp", 445)]}, None), "tcp/445")

    def test_icmp_and_plain_web_unaffected(self):
        self.assertEqual(core.display_ports({"ports": [("icmp", None)]}, "10.0.0.9"), "icmp")
        self.assertEqual(core.display_ports({"ports": [("tcp", 8080)]}, "10.0.0.9"), "tcp/8080")

    def test_format_is_proto_slash_port(self):
        # canonical proto/port (NOT the old GUI/app 'port/proto'), so all surfaces agree
        self.assertEqual(core.display_ports({"ports": [("tcp", 80)]}), "tcp/80")

    def test_no_ports_is_empty(self):
        self.assertEqual(core.display_ports({"ports": []}, "10.0.0.9"), "")


if __name__ == "__main__":
    unittest.main()
