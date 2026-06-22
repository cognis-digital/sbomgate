"""Offline tests for the CISA-KEV + EPSS + OSV feed enrichment layer.

These tests NEVER touch the network. They point ``COGNIS_FEEDS_CACHE`` at a
trimmed fixture cache committed under ``tests/fixtures/feeds-cache`` and call
the feed API with ``offline=True``, so CI stays green air-gapped.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

FIXTURE_CACHE = os.path.join(HERE, "fixtures", "feeds-cache")
# Route every feed read at the committed fixture cache before importing.
os.environ["COGNIS_FEEDS_CACHE"] = FIXTURE_CACHE

from sbomgate import feeds  # noqa: E402
from sbomgate.core import Finding, match_vulnerabilities, load_sbom, load_advisories, gate  # noqa: E402
from sbomgate.cli import main  # noqa: E402

DEMO = os.path.join(ROOT, "demos", "11-feeds-kev-epss-enrichment")
SBOM = os.path.join(DEMO, "sbom.json")
ADV = os.path.join(DEMO, "advisories.json")


class TestCatalogScope(unittest.TestCase):
    def test_only_relevant_feeds(self):
        ids = [f["id"] for f in feeds.catalog()]
        self.assertEqual(set(ids), {"cisa-kev", "epss", "osv"})

    def test_is_relevant(self):
        self.assertTrue(feeds.is_relevant("cisa-kev"))
        self.assertFalse(feeds.is_relevant("ofac-sdn"))

    def test_catalog_urls_are_real_sources(self):
        by_id = {f["id"]: f for f in feeds.catalog()}
        self.assertIn("cisa.gov", by_id["cisa-kev"]["url"])
        self.assertIn("first.org", by_id["epss"]["url"])
        self.assertIn("osv.dev", by_id["osv"]["url"])


class TestKevOffline(unittest.TestCase):
    def test_kev_set_from_fixture(self):
        kev = feeds.kev_cve_set(offline=True)
        self.assertIn("CVE-2021-44228", kev)
        self.assertIn("CVE-2014-0160", kev)
        self.assertIn("CVE-2022-22965", kev)


class TestEpssOffline(unittest.TestCase):
    def test_scores_from_fixture(self):
        scores = feeds.epss_scores(
            ["CVE-2021-44228", "CVE-2014-0160", "CVE-9999-0000"], offline=True
        )
        self.assertAlmostEqual(scores["CVE-2021-44228"], 0.975, places=3)
        self.assertAlmostEqual(scores["CVE-2014-0160"], 0.944, places=3)
        self.assertNotIn("CVE-9999-0000", scores)  # not in fixture

    def test_ignores_non_cve_ids(self):
        self.assertEqual(feeds.epss_scores(["GHSA-req-2015"], offline=True), {})


class TestOsvOfflineNoop(unittest.TestCase):
    def test_osv_offline_returns_empty(self):
        # OSV is a per-package POST we do not pre-cache; offline => [].
        self.assertEqual(feeds.osv_query("requests", "2.5.0", "pypi", offline=True), [])


class TestEnrichment(unittest.TestCase):
    def _findings(self):
        comps = load_sbom(SBOM)
        adv = load_advisories(ADV)
        return match_vulnerabilities(comps, adv)

    def test_kev_escalates_to_critical(self):
        findings = self._findings()
        # before enrichment everything is "high"
        self.assertTrue(all(f.severity == "high" for f in findings))
        summary = feeds.enrich_findings(findings, offline=True)
        by_comp = {f.component: f for f in findings}
        # log4j / spring / openssl are on the KEV fixture -> escalated critical
        self.assertEqual(by_comp["log4j-core"].severity, "critical")
        self.assertEqual(by_comp["spring-core"].severity, "critical")
        self.assertEqual(by_comp["openssl"].severity, "critical")
        # requests has no CVE on KEV -> stays high
        self.assertEqual(by_comp["requests"].severity, "high")
        self.assertEqual(summary["kev"], 3)
        self.assertEqual(set(summary["kev_cves"]),
                         {"CVE-2021-44228", "CVE-2022-22965", "CVE-2014-0160"})

    def test_kev_and_epss_tags_in_detail(self):
        findings = self._findings()
        feeds.enrich_findings(findings, offline=True)
        log4j = next(f for f in findings if f.component == "log4j-core")
        self.assertIn("KEV", log4j.detail)
        self.assertIn("EPSS=", log4j.detail)

    def test_epss_attached_to_finding(self):
        findings = self._findings()
        feeds.enrich_findings(findings, offline=True)
        log4j = next(f for f in findings if f.component == "log4j-core")
        self.assertTrue(getattr(log4j, "known_exploited", False))
        self.assertAlmostEqual(getattr(log4j, "epss"), 0.975, places=3)

    def test_no_vuln_findings_is_safe(self):
        out = feeds.enrich_findings(
            [Finding(kind="added", component="x", severity="low")], offline=True
        )
        self.assertEqual(out["enriched"], 0)


class TestEnrichedGate(unittest.TestCase):
    def test_enrichment_can_flip_gate_to_critical(self):
        comps = load_sbom(SBOM)
        adv = load_advisories(ADV)
        findings = match_vulnerabilities(comps, adv)
        feeds.enrich_findings(findings, offline=True)
        # KEV escalation means a critical-only gate now fails.
        self.assertTrue(gate(findings, fail_on="critical"))


class TestCliOffline(unittest.TestCase):
    def test_feeds_list(self):
        rc = main(["feeds", "list"])
        self.assertEqual(rc, 0)

    def test_feeds_get_offline(self):
        rc = main(["feeds", "get", "cisa-kev", "--offline"])
        self.assertEqual(rc, 0)

    def test_feeds_get_rejects_irrelevant(self):
        rc = main(["feeds", "get", "ofac-sdn", "--offline"])
        self.assertEqual(rc, 1)

    def test_scan_enrich_offline_exit_nonzero(self):
        rc = main(["vulns", SBOM, ADV, "--enrich", "--offline", "--format", "json"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
