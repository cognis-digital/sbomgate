"""Deeper unit tests for the core matcher, version semantics, parsing, and gate.

All offline, pure stdlib + unittest. Complements test_smoke.py.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sbomgate import core  # noqa: E402
from sbomgate.core import (  # noqa: E402
    Component,
    Finding,
    DiffResult,
    parse_sbom,
    diff_sboms,
    match_vulnerabilities,
    gate,
    to_sarif,
    _sev_rank,
    _version_matches,
    _cmp_version,
    _affected,
    _ecosystem_from_purl,
    _extract_maintainer,
    TOOL_NAME,
    TOOL_VERSION,
)


class TestToolIdentity(unittest.TestCase):
    def test_name_and_version(self):
        self.assertEqual(TOOL_NAME, "sbomgate")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+")


class TestSevRank(unittest.TestCase):
    def test_order(self):
        self.assertLess(_sev_rank("critical"), _sev_rank("high"))
        self.assertLess(_sev_rank("high"), _sev_rank("medium"))
        self.assertLess(_sev_rank("medium"), _sev_rank("low"))

    def test_unknown_and_blank(self):
        self.assertEqual(_sev_rank("bananas"), _sev_rank("unknown"))
        self.assertEqual(_sev_rank(""), _sev_rank("unknown"))

    def test_case_and_whitespace(self):
        self.assertEqual(_sev_rank("  HIGH "), _sev_rank("high"))


class TestVersionCompare(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(_cmp_version("1.0.0", "1.0.0"), 0)
        self.assertEqual(_cmp_version("1.0.0", "1.0.1"), -1)
        self.assertEqual(_cmp_version("2.0.0", "1.9.9"), 1)

    def test_numeric_not_lexical(self):
        # 2.10.0 > 2.9.0 numerically (lexical would say otherwise)
        self.assertEqual(_cmp_version("2.10.0", "2.9.0"), 1)

    def test_prerelease_sorts_after_numeric(self):
        # 1.0.0-rc has a non-numeric chunk which sorts after pure numeric
        self.assertEqual(_cmp_version("1.0.0", "1.0"), 1)


class TestVersionMatches(unittest.TestCase):
    def test_operators(self):
        self.assertTrue(_version_matches("2.5.0", "<2.20.0"))
        self.assertFalse(_version_matches("2.21.0", "<2.20.0"))
        self.assertTrue(_version_matches("2.20.0", ">=2.20.0"))
        self.assertTrue(_version_matches("2.5.0", "==2.5.0"))
        self.assertTrue(_version_matches("2.5.0", "2.5.0"))  # bare = exact
        self.assertFalse(_version_matches("2.5.1", "2.5.0"))
        self.assertTrue(_version_matches("3.0.0", ">2.9.9"))
        self.assertTrue(_version_matches("2.5.0", "<=2.5.0"))

    def test_blank_constraint_or_version(self):
        self.assertFalse(_version_matches("1.0", ""))
        self.assertFalse(_version_matches("", "<2.0"))

    def test_equals_alias(self):
        self.assertTrue(_version_matches("1.2.3", "=1.2.3"))


class TestAffected(unittest.TestCase):
    def test_string_is_anded(self):
        self.assertTrue(_affected("2.5.0", ">=2.0,<2.31.0"))
        self.assertFalse(_affected("1.9.0", ">=2.0,<2.31.0"))

    def test_list_is_ored(self):
        self.assertTrue(_affected("3.0.0", ["<1.0", ">=3.0,<4.0"]))
        self.assertFalse(_affected("2.0.0", ["<1.0", ">=3.0,<4.0"]))

    def test_non_string_entries_ignored(self):
        self.assertFalse(_affected("1.0", [123, None]))

    def test_empty(self):
        self.assertFalse(_affected("1.0", []))
        self.assertFalse(_affected("1.0", ""))


class TestPurlAndMaintainer(unittest.TestCase):
    def test_eco_from_purl(self):
        self.assertEqual(_ecosystem_from_purl("pkg:pypi/requests@2.0"), "pypi")
        self.assertEqual(_ecosystem_from_purl("pkg:maven/g/a@1"), "maven")
        self.assertEqual(_ecosystem_from_purl("not-a-purl"), "")

    def test_maintainer_strips_org_prefix(self):
        self.assertEqual(_extract_maintainer({"supplier": "Organization: Acme"}), "Acme")
        self.assertEqual(_extract_maintainer({"originator": "Person: Jane"}), "Jane")
        self.assertEqual(_extract_maintainer({"publisher": "PlainName"}), "PlainName")


class TestParseSbomShapes(unittest.TestCase):
    def test_bare_list(self):
        comps = parse_sbom([{"name": "a", "version": "1"}, {"nope": True}])
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0].name, "a")

    def test_spdx_packages(self):
        data = {"packages": [{"packageName": "lodash", "versionInfo": "4.17.0",
                              "supplier": "Organization: npm"}]}
        comps = parse_sbom(data)
        self.assertEqual(comps[0].name, "lodash")
        self.assertEqual(comps[0].version, "4.17.0")
        self.assertEqual(comps[0].maintainer, "npm")

    def test_cyclonedx_type_not_treated_as_ecosystem(self):
        data = {"components": [{"name": "x", "version": "1", "type": "library",
                               "purl": "pkg:npm/x@1"}]}
        comps = parse_sbom(data)
        self.assertEqual(comps[0].ecosystem, "npm")

    def test_unrecognized_raises(self):
        with self.assertRaises(ValueError):
            parse_sbom({"foo": "bar"})
        with self.assertRaises(ValueError):
            parse_sbom(42)


class TestComponentKey(unittest.TestCase):
    def test_key_with_and_without_ecosystem(self):
        self.assertEqual(Component(name="Req", ecosystem="PyPI").key(), "pypi:req")
        self.assertEqual(Component(name="Req").key(), "req")


class TestDiffResult(unittest.TestCase):
    def setUp(self):
        self.old = [Component(name="a", version="1", ecosystem="pypi"),
                    Component(name="b", version="1", ecosystem="pypi")]
        self.new = [Component(name="a", version="2", ecosystem="pypi"),
                    Component(name="c", version="1", ecosystem="pypi")]
        self.d = diff_sboms(self.old, self.new)

    def test_summary_counts(self):
        s = self.d.summary()
        self.assertEqual(s.get("added"), 1)
        self.assertEqual(s.get("removed"), 1)
        self.assertEqual(s.get("version-change"), 1)

    def test_max_severity(self):
        self.assertEqual(self.d.max_severity(), "low")

    def test_to_dict_round_trips(self):
        d = self.d.to_dict()
        self.assertEqual(d["old_count"], 2)
        self.assertEqual(d["new_count"], 2)
        self.assertIn("findings", d)

    def test_maintainer_blank_one_side_not_flagged(self):
        old = [Component(name="x", version="1", maintainer="acme", ecosystem="pypi")]
        new = [Component(name="x", version="1", maintainer="", ecosystem="pypi")]
        d = diff_sboms(old, new)
        self.assertFalse(any(f.kind == "maintainer-change" for f in d.findings))


class TestMatchVulnerabilities(unittest.TestCase):
    def test_ecosystem_scoping(self):
        comps = [Component(name="requests", version="2.5.0", ecosystem="npm")]
        adv = [{"id": "X", "name": "requests", "ecosystem": "pypi",
                "severity": "high", "affected": ["<2.20.0"]}]
        # ecosystem mismatch -> no finding
        self.assertEqual(match_vulnerabilities(comps, adv), [])

    def test_severity_sort_order(self):
        comps = [Component(name="a", version="1", ecosystem="pypi"),
                 Component(name="b", version="1", ecosystem="pypi")]
        adv = [
            {"id": "L", "name": "a", "severity": "low", "affected": ["<2"]},
            {"id": "C", "name": "b", "severity": "critical", "affected": ["<2"]},
        ]
        findings = match_vulnerabilities(comps, adv)
        self.assertEqual(findings[0].severity, "critical")

    def test_advisory_alias_id_fields(self):
        comps = [Component(name="a", version="1", ecosystem="pypi")]
        adv = [{"cve": "CVE-2020-0001", "name": "a", "severity": "high", "affected": ["<2"]}]
        findings = match_vulnerabilities(comps, adv)
        self.assertEqual(findings[0].advisory_id, "CVE-2020-0001")


class TestGate(unittest.TestCase):
    def _f(self, sev):
        return Finding(kind="vulnerability", component="x", severity=sev)

    def test_thresholds(self):
        self.assertTrue(gate([self._f("critical")], fail_on="high"))
        self.assertTrue(gate([self._f("high")], fail_on="high"))
        self.assertFalse(gate([self._f("medium")], fail_on="high"))
        self.assertTrue(gate([self._f("medium")], fail_on="medium"))
        self.assertFalse(gate([self._f("low")], fail_on="medium"))

    def test_empty(self):
        self.assertFalse(gate([], fail_on="low"))


class TestSarifExtra(unittest.TestCase):
    def test_unknown_kind_gets_generic_rule(self):
        log = to_sarif([Finding(kind="weird-kind", component="x", severity="low")])
        rule_ids = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("SBOMGATE-WEIRD-KIND", rule_ids)

    def test_security_severity_bands(self):
        log = to_sarif([
            Finding(kind="vulnerability", component="a", severity="critical"),
            Finding(kind="vulnerability", component="b", severity="medium"),
        ])
        results = log["runs"][0]["results"]
        bands = {r["properties"]["severity"]: r["properties"]["security-severity"]
                 for r in results}
        self.assertEqual(bands["critical"], "9.5")
        self.assertEqual(bands["medium"], "5.5")


if __name__ == "__main__":
    unittest.main()
