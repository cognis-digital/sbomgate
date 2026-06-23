"""Offline tests for matching SBOM components against the bundled 262k OSV DB.

No network. These prove REAL lookups resolve in the bundled
``sbomgate/cognis_vulndb.jsonl.gz`` — e.g. log4j-core@2.14.1 -> CVE-2021-44228.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sbomgate.core import Component, Finding  # noqa: E402
from sbomgate.vulndb_local import VulnDB  # noqa: E402
from sbomgate.vulnmatch import (  # noqa: E402
    DBMatcher,
    match_against_db,
    _cvss_band,
    _short_names,
    _norm_eco,
    _primary_cve,
)


class TestShortNames(unittest.TestCase):
    def test_maven_coordinate_short_name(self):
        names = _short_names("org.apache.logging.log4j:log4j-core")
        self.assertIn("org.apache.logging.log4j:log4j-core", names)
        self.assertIn("log4j-core", names)

    def test_go_module_path_short_name(self):
        names = _short_names("github.com/gin-gonic/gin")
        self.assertIn("gin", names)

    def test_plain_name_passthrough(self):
        self.assertEqual(_short_names("lodash"), ["lodash"])

    def test_empty(self):
        self.assertEqual(_short_names(""), [])


class TestEcoNormalize(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(_norm_eco("pip"), "pypi")
        self.assertEqual(_norm_eco("golang"), "go")
        self.assertEqual(_norm_eco("java"), "maven")
        self.assertEqual(_norm_eco("rust"), "crates.io")
        self.assertEqual(_norm_eco("ruby"), "rubygems")

    def test_unknown_passthrough_lowercased(self):
        self.assertEqual(_norm_eco("Conda"), "conda")


class TestCvssBand(unittest.TestCase):
    def test_numeric_bands(self):
        self.assertEqual(_cvss_band("9.8"), "critical")
        self.assertEqual(_cvss_band("7.5"), "high")
        self.assertEqual(_cvss_band("5.0"), "medium")
        self.assertEqual(_cvss_band("2.1"), "low")
        self.assertEqual(_cvss_band("0"), "none")

    def test_vector_with_three_highs_network(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        self.assertEqual(_cvss_band(v), "critical")

    def test_textual(self):
        self.assertEqual(_cvss_band("HIGH"), "high")
        self.assertEqual(_cvss_band("moderate"), "high")  # moderate -> high
        self.assertEqual(_cvss_band("low"), "low")

    def test_empty_is_unknown(self):
        self.assertEqual(_cvss_band(""), "unknown")


class TestPrimaryCve(unittest.TestCase):
    def test_prefers_cve_alias(self):
        rec = {"id": "GHSA-xxxx", "aliases": ["GHSA-xxxx", "CVE-2021-44228"]}
        self.assertEqual(_primary_cve(rec), "CVE-2021-44228")

    def test_falls_back_to_id(self):
        rec = {"id": "GHSA-only", "aliases": []}
        self.assertEqual(_primary_cve(rec), "GHSA-only")


class TestRealDbLookups(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = VulnDB()

    def test_db_ships_260k_plus(self):
        self.assertGreaterEqual(self.db.count(), 260000)

    def test_log4shell_by_cve(self):
        hits = self.db.by_cve("CVE-2021-44228")
        self.assertTrue(hits)
        rec = hits[0]
        self.assertIn("CVE-2021-44228", rec["aliases"])
        self.assertEqual(rec["ecosystem"], "Maven")
        self.assertTrue(any("log4j-core" in p for p in rec["packages"]))

    def test_cve_lookup_is_case_insensitive(self):
        self.assertTrue(self.db.by_cve("cve-2021-44228"))

    def test_unknown_cve_returns_empty(self):
        self.assertEqual(self.db.by_cve("CVE-0000-00000"), [])

    def test_search_finds_log4j(self):
        results = self.db.search("Log4j", limit=5)
        self.assertTrue(results)
        self.assertTrue(all("log4j" in r["summary"].lower() for r in results))


class TestComponentMatching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matcher = DBMatcher()

    def test_log4j_component_matches_log4shell(self):
        comp = Component(name="log4j-core", version="2.14.1", ecosystem="maven")
        findings = self.matcher.match_component(comp)
        self.assertTrue(findings)
        ids = {f.advisory_id for f in findings}
        self.assertIn("CVE-2021-44228", ids)
        for f in findings:
            self.assertEqual(f.kind, "vulnerability")
            self.assertEqual(f.component, "log4j-core")

    def test_findings_are_finding_objects(self):
        comp = Component(name="log4j-core", version="2.14.1", ecosystem="maven")
        findings = self.matcher.match_component(comp)
        self.assertIsInstance(findings[0], Finding)

    def test_ecosystem_scope_excludes_mismatch(self):
        # log4j-core lives in Maven; scoping to pypi should drop it.
        comp = Component(name="log4j-core", version="2.14.1", ecosystem="pypi")
        findings = self.matcher.match_component(comp)
        self.assertEqual(findings, [])

    def test_no_ecosystem_still_matches(self):
        comp = Component(name="log4j-core", version="2.14.1", ecosystem="")
        findings = self.matcher.match_component(comp)
        self.assertTrue(findings)

    def test_unknown_package_no_findings(self):
        comp = Component(name="totally-not-a-real-pkg-zzz", version="1.0", ecosystem="npm")
        self.assertEqual(self.matcher.match_component(comp), [])

    def test_match_dedupes_records(self):
        comp = Component(name="log4j-core", version="2.14.1", ecosystem="maven")
        findings = self.matcher.match_component(comp)
        ids = [f.advisory_id for f in findings]
        self.assertEqual(len(ids), len(set(ids)))

    def test_match_against_db_sorts_by_severity(self):
        comp = Component(name="log4j-core", version="2.14.1", ecosystem="maven")
        findings = match_against_db([comp])
        from sbomgate.core import _sev_rank
        ranks = [_sev_rank(f.severity) for f in findings]
        self.assertEqual(ranks, sorted(ranks))

    def test_lodash_npm_resolves(self):
        comp = Component(name="lodash", version="4.17.11", ecosystem="npm")
        findings = self.matcher.match_component(comp)
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()
