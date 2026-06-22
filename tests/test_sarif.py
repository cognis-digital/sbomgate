"""Tests for SARIF 2.1.0 export and the new demo fixtures.

No network. Pure stdlib + unittest.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sbomgate import (  # noqa: E402
    load_sbom,
    load_advisories,
    diff_sboms,
    match_vulnerabilities,
    to_sarif,
)
from sbomgate.cli import main  # noqa: E402

DEMOS = os.path.join(ROOT, "demos")


def _capture(argv):
    """Run the CLI capturing stdout; return (rc, stdout)."""
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


class TestSarifShape(unittest.TestCase):
    def setUp(self):
        demo = os.path.join(DEMOS, "01-basic")
        comps = load_sbom(os.path.join(demo, "sbom-new.json"))
        adv = load_advisories(os.path.join(demo, "advisories.json"))
        self.findings = match_vulnerabilities(comps, adv)
        self.log = to_sarif(self.findings, tool_name="sbomgate", tool_version="9.9.9")

    def test_top_level_envelope(self):
        self.assertEqual(self.log["version"], "2.1.0")
        self.assertIn("$schema", self.log)
        self.assertEqual(len(self.log["runs"]), 1)

    def test_driver_metadata(self):
        driver = self.log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "sbomgate")
        self.assertEqual(driver["version"], "9.9.9")
        self.assertTrue(driver["informationUri"].startswith("https://"))

    def test_results_count_matches_findings(self):
        results = self.log["runs"][0]["results"]
        self.assertEqual(len(results), len(self.findings))

    def test_levels_and_security_severity(self):
        results = self.log["runs"][0]["results"]
        crit = next(r for r in results if r["properties"]["severity"] == "critical")
        self.assertEqual(crit["level"], "error")
        self.assertEqual(crit["properties"]["security-severity"], "9.5")
        # every result references a defined rule
        rule_ids = {r["id"] for r in self.log["runs"][0]["tool"]["driver"]["rules"]}
        for r in results:
            self.assertIn(r["ruleId"], rule_ids)

    def test_vuln_result_has_fingerprint(self):
        results = self.log["runs"][0]["results"]
        vuln = next(r for r in results if r["properties"]["kind"] == "vulnerability")
        self.assertIn("partialFingerprints", vuln)
        self.assertIn("advisory_id", vuln["properties"])

    def test_empty_findings_is_valid_sarif(self):
        log = to_sarif([])
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(log["runs"][0]["results"], [])

    def test_diff_kinds_become_rules(self):
        demo = os.path.join(DEMOS, "01-basic")
        diff = diff_sboms(
            load_sbom(os.path.join(demo, "sbom-old.json")),
            load_sbom(os.path.join(demo, "sbom-new.json")),
        )
        log = to_sarif(diff.findings)
        rule_ids = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("SBOMGATE-MAINTAINER", rule_ids)
        self.assertIn("SBOMGATE-ADDED", rule_ids)


class TestSarifCli(unittest.TestCase):
    def test_cli_emits_parseable_sarif(self):
        demo = os.path.join(DEMOS, "01-basic")
        rc, out = _capture([
            "scan", os.path.join(demo, "sbom-new.json"),
            "--advisories", os.path.join(demo, "advisories.json"),
            "--format", "sarif",
        ])
        self.assertEqual(rc, 1)  # gate fails on the critical
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertGreater(len(doc["runs"][0]["results"]), 0)


class TestNewDemosFire(unittest.TestCase):
    """Each new demo must actually produce its documented outcome."""

    def _scan(self, sub, new, old=None, adv=None, fail_on="high"):
        argv = ["scan", os.path.join(DEMOS, sub, new)]
        if old:
            argv += ["--old", os.path.join(DEMOS, sub, old)]
        if adv:
            argv += ["--advisories", os.path.join(DEMOS, sub, adv)]
        argv += ["--fail-on", fail_on, "--format", "json"]
        rc, out = _capture(argv)
        return rc, json.loads(out)

    def _vulns(self, sub, sbom, adv, fail_on="high"):
        rc, out = _capture([
            "vulns", os.path.join(DEMOS, sub, sbom),
            os.path.join(DEMOS, sub, adv),
            "--fail-on", fail_on, "--format", "json",
        ])
        return rc, json.loads(out)

    def test_04_spdx_node(self):
        rc, doc = self._vulns("04-spdx-format-nodejs", "sbom.json", "advisories.json")
        self.assertEqual(rc, 1)
        comps = {f["component"] for f in doc["findings"]}
        self.assertEqual(comps, {"lodash", "minimist"})

    def test_05_downgrade_reintroduces_critical(self):
        rc, doc = self._scan(
            "05-transitive-critical", "sbom-new.json",
            old="sbom-old.json", adv="advisories.json",
        )
        self.assertEqual(rc, 1)
        sev = {f["component"]: f["severity"]
               for f in doc["findings"] if f["kind"] == "vulnerability"}
        self.assertEqual(sev.get("PyYAML"), "critical")

    def test_06_clean_build_passes(self):
        rc, doc = self._scan(
            "06-clean-build-passes", "sbom-new.json",
            old="sbom-old.json", adv="advisories.json",
        )
        self.assertEqual(rc, 0)
        self.assertEqual(doc["gate"], "pass")
        kinds = {f["kind"] for f in doc["findings"]}
        self.assertNotIn("vulnerability", kinds)

    def test_07_ecosystem_scoping(self):
        rc, doc = self._vulns("07-ecosystem-mismatch", "sbom.json", "advisories.json")
        self.assertEqual(rc, 1)
        # exactly one match: the pypi requests, not the npm one
        self.assertEqual(doc["finding_count"], 1)
        self.assertEqual(doc["findings"][0]["component"], "requests")

    def test_08_multi_ecosystem(self):
        rc, doc = self._scan(
            "08-multi-ecosystem-monorepo", "sbom-new.json",
            old="sbom-old.json", adv="advisories.json", fail_on="critical",
        )
        self.assertEqual(rc, 1)  # Text4Shell critical
        vulns = {f["component"] for f in doc["findings"]
                 if f["kind"] == "vulnerability"}
        self.assertIn("org.apache.commons:commons-text", vulns)
        self.assertIn("axios", vulns)
        mc = [f for f in doc["findings"] if f["kind"] == "maintainer-change"]
        self.assertEqual({f["component"] for f in mc}, {"internal-auth"})

    def test_09_sarif_demo_levels(self):
        rc, out = _capture([
            "vulns",
            os.path.join(DEMOS, "09-sarif-codescanning", "sbom.json"),
            os.path.join(DEMOS, "09-sarif-codescanning", "advisories.json"),
            "--format", "sarif",
        ])
        self.assertEqual(rc, 1)
        doc = json.loads(out)
        self.assertEqual(len(doc["runs"][0]["results"]), 3)

    def test_10_range_operators(self):
        rc, doc = self._vulns(
            "10-version-range-and-gate", "sbom.json", "advisories.json",
            fail_on="low",
        )
        self.assertEqual(rc, 1)
        matched = {f["component"] for f in doc["findings"]}
        self.assertEqual(matched, {"alpha", "bravo", "charlie", "delta"})
        self.assertNotIn("echo", matched)  # 5.0.0 not < 5.0.0


if __name__ == "__main__":
    unittest.main()
