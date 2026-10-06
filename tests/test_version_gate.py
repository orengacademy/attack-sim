"""Offline tests for the version gate (core.enforce_latest_version & helpers).

Pure-stdlib, localhost-only, OFFLINE: every test monkeypatches the network fetch
(core.fetch_latest_version), so nothing here touches the network. This mirrors the
production invariant that the gate only fetches from a front-end's main() — never
at import — so importing core / running the suite stays offline.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import core  # noqa: E402


class SemverParse(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(core._parse_semver("1.9.0"), (1, 9, 0))
        self.assertEqual(core._parse_semver("v1.9.0"), (1, 9, 0))
        self.assertEqual(core._parse_semver("1.9.0-rc1"), (1, 9, 0))  # suffix ignored
        self.assertIsNone(core._parse_semver("not-a-version"))
        self.assertIsNone(core._parse_semver(""))
        self.assertIsNone(core._parse_semver(None))


class OutdatedCompare(unittest.TestCase):
    def test_compare(self):
        self.assertTrue(core.version_is_outdated("1.8.0", "1.9.0"))
        self.assertTrue(core.version_is_outdated("1.9.0", "1.10.0"))   # numeric, not lexical
        self.assertFalse(core.version_is_outdated("1.9.0", "1.9.0"))
        self.assertFalse(core.version_is_outdated("1.10.0", "1.9.0"))  # ahead
        # unknown/unparseable latest must NEVER read as outdated (caller fail-opens)
        self.assertFalse(core.version_is_outdated("1.9.0", None))
        self.assertFalse(core.version_is_outdated("1.9.0", "garbage"))


class EnforceGate(unittest.TestCase):
    """enforce_latest_version() across every branch, with the fetch stubbed."""

    def setUp(self):
        self._real_fetch = core.fetch_latest_version
        self._saved_env = {k: os.environ.get(k)
                           for k in ("HARNESS_SKIP_VERSION_CHECK", "HARNESS_REQUIRE_LATEST")}
        for k in self._saved_env:
            os.environ.pop(k, None)

    def tearDown(self):
        core.fetch_latest_version = self._real_fetch
        for k, v in self._saved_env.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def _stub(self, value):
        core.fetch_latest_version = lambda *a, **k: value

    def _enforce(self, **kw):
        kw.setdefault("log", lambda m: None)
        return core.enforce_latest_version(**kw)

    def test_outdated_blocks(self):
        self._stub("99.0.0")
        with self.assertRaises(SystemExit) as cm:
            self._enforce()
        self.assertEqual(cm.exception.code, 3)

    def test_outdated_can_report_without_exit(self):
        self._stub("99.0.0")
        self.assertFalse(self._enforce(exit_on_outdated=False))

    def test_current_ok(self):
        self._stub(core.VERSION)
        self.assertTrue(self._enforce())

    def test_ahead_ok(self):
        self._stub("0.0.1")
        self.assertTrue(self._enforce())

    def test_offline_fail_open(self):
        self._stub(None)
        self.assertIsNone(self._enforce())          # warn + run, no exit

    def test_offline_strict_blocks(self):
        self._stub(None)
        os.environ["HARNESS_REQUIRE_LATEST"] = "1"
        with self.assertRaises(SystemExit) as cm:
            self._enforce()
        self.assertEqual(cm.exception.code, 3)

    def test_skip_env_bypasses_even_when_outdated(self):
        self._stub("99.0.0")
        os.environ["HARNESS_SKIP_VERSION_CHECK"] = "1"
        self.assertTrue(self._enforce())            # no exit despite being outdated


class VersionSource(unittest.TestCase):
    def test_version_matches_file(self):
        """core.VERSION is sourced from the committed VERSION file."""
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VERSION")
        with open(path) as f:
            self.assertEqual(core.VERSION, f.read().strip())


if __name__ == "__main__":
    unittest.main()
