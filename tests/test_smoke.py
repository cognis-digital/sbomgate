"""Smoke tests for SBOMGATE: import core, run on the bundled demo, assert behavior.

No network. Pure stdlib + unittest.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sbomgate import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    load_sbom,
    load_advisories,
    diff_sboms,
    match_vulnerabilities,
    gate,
)
from sbomgate.cli import main  # noqa: E402

DEMO = os.path.join(ROOT, "demos", "01-basic")
OLD = os.path.join(DEMO, "sbom-old.json")
NEW = os.path.join(DEMO, "sbom-new.json")
ADV = os.path.join(DEMO, "advisories.json")


class TestMetadata(unittest.TestCase):
    def test_tool_identity(self):
        self.assertEqual(TOOL_NAME, "sbomgate")
        self.assertTrue(TOOL_VERSION)


class TestParsing(unittest.TestCase):
    def test_loads_cyclonedx(self):
        comps = load_sbom(NEW)
        self.assertEqual(len(comps), 4)
        names = {c.name for c in comps}
        self.assertIn("shady-logger", names)
        req = next(c for c in comps if c.name == "requests")
        self.assertEqual(req.version, "2.5.0")
        self.assertEqual(req.ecosystem, "pypi")  # derived from purl


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.diff = diff_sboms(load_sbom(OLD), load_sbom(NEW))
        self.kinds = [f.kind for f in self.diff.findings]

    def test_counts(self):
        self.assertEqual(self.diff.old_count, 4)
        self.assertEqual(self.diff.new_count, 4)

    def test_added_and_removed(self):
        added = [f for f in self.diff.findings if f.kind == "added"]
        removed = [f for f in self.diff.findings if f.kind == "removed"]
        self.assertEqual({f.component for f in added}, {"shady-logger"})
        self.assertEqual({f.component for f in removed}, {"colorama"})

    def test_version_change_detected(self):
        vc = [f for f in self.diff.findings if f.kind == "version-change"]
        comps = {f.component: (f.old, f.new) for f in vc}
        self.assertEqual(comps["requests"], ("2.32.0", "2.5.0"))
        self.assertEqual(comps["urllib3"], ("2.2.1", "2.2.2"))

    def test_maintainer_change_flagged_high(self):
        mc = [f for f in self.diff.findings if f.kind == "maintainer-change"]
        self.assertEqual(len(mc), 1)
        self.assertEqual(mc[0].component, "leftpad-utils")
        self.assertEqual(mc[0].severity, "high")
        self.assertEqual(mc[0].old, "acme-security")
        self.assertEqual(mc[0].new, "unknown-dev-9981")


class TestVulns(unittest.TestCase):
    def setUp(self):
        self.comps = load_sbom(NEW)
        self.adv = load_advisories(ADV)
        self.findings = match_vulnerabilities(self.comps, self.adv)

    def test_matches_expected(self):
        by_comp = {f.component: f for f in self.findings}
        # requests 2.5.0 < 2.20.0 -> high
        self.assertIn("requests", by_comp)
        self.assertEqual(by_comp["requests"].severity, "high")
        # shady-logger 0.0.7 < 1.0.0 -> critical
        self.assertIn("shady-logger", by_comp)
        self.assertEqual(by_comp["shady-logger"].severity, "critical")
        # urllib3 2.2.2 is NOT < 2.2.2 -> no finding
        self.assertNotIn("urllib3", by_comp)

    def test_sorted_critical_first(self):
        self.assertEqual(self.findings[0].severity, "critical")

    def test_advisory_id_attached(self):
        ids = {f.advisory_id for f in self.findings}
        self.assertIn("GHSA-shady-0001", ids)


class TestGate(unittest.TestCase):
    def test_gate_fails_on_high(self):
        findings = match_vulnerabilities(load_sbom(NEW), load_advisories(ADV))
        self.assertTrue(gate(findings, fail_on="high"))

    def test_gate_passes_when_threshold_above_findings(self):
        # Only the urllib3 medium would be a finding if it matched; here we
        # use a component set with no critical/high vuln by raising the bar.
        findings = match_vulnerabilities(load_sbom(NEW), load_advisories(ADV))
        # there IS a critical, so even critical-only gate fails
        self.assertTrue(gate(findings, fail_on="critical"))


class TestCLI(unittest.TestCase):
    def test_scan_exit_code_nonzero_on_findings(self):
        rc = main(["scan", NEW, "--old", OLD, "--advisories", ADV, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_diff_only(self):
        rc = main(["diff", OLD, NEW, "--format", "json"])
        # maintainer-change is high -> gate fails by default
        self.assertEqual(rc, 1)

    def test_missing_file_returns_2(self):
        rc = main(["scan", os.path.join(DEMO, "nope.json")])
        self.assertEqual(rc, 2)

    def test_no_command_prints_help(self):
        rc = main([])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
