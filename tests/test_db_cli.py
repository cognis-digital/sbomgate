"""Tests for the `sbomgate db` subcommand and the --match-db scan flag.

All offline. Proves the bundled 262k OSV DB is wired into the CLI and that a
real Maven log4j-core SBOM resolves to Log4Shell with no advisory feed.
"""
import io
import contextlib
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sbomgate.cli import main  # noqa: E402


def _capture(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def _write_sbom(components):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"bomFormat": "CycloneDX", "components": components}, fh)
    return path


class TestDbCount(unittest.TestCase):
    def test_count_prints_total(self):
        rc, out = _capture(["db", "count"])
        self.assertEqual(rc, 0)
        self.assertIn("vulnerabilities", out)
        n = int(out.split()[0])
        self.assertGreaterEqual(n, 260000)

    def test_bare_db_defaults_to_count(self):
        rc, out = _capture(["db"])
        self.assertEqual(rc, 0)
        self.assertIn("bundled offline DB", out)


class TestDbCve(unittest.TestCase):
    def test_log4shell_resolves(self):
        rc, out = _capture(["db", "cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)
        recs = json.loads(out)
        self.assertTrue(recs)
        self.assertIn("CVE-2021-44228", recs[0]["aliases"])

    def test_unknown_cve_exit_1(self):
        rc, out = _capture(["db", "cve", "CVE-0000-00000"])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out), [])


class TestDbPackage(unittest.TestCase):
    def test_short_name_fallback_resolves_maven(self):
        # log4j-core is stored as org.apache.logging.log4j:log4j-core
        rc, out = _capture(["db", "package", "log4j-core"])
        self.assertEqual(rc, 0)
        recs = json.loads(out)
        self.assertTrue(recs)
        aliases = {a for r in recs for a in r.get("aliases", [])}
        self.assertIn("CVE-2021-44228", aliases)


class TestDbSearch(unittest.TestCase):
    def test_search_log4j(self):
        rc, out = _capture(["db", "search", "Log4j", "--limit", "3"])
        self.assertEqual(rc, 0)
        recs = json.loads(out)
        self.assertTrue(0 < len(recs) <= 3)


class TestDbMatch(unittest.TestCase):
    def test_match_maven_log4j(self):
        path = _write_sbom([{
            "name": "log4j-core", "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "type": "library",
        }])
        try:
            rc, out = _capture(["db", "match", path, "--format", "json"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)  # gate fails: criticals present
        doc = json.loads(out)
        ids = {f["advisory_id"] for f in doc["findings"]}
        self.assertIn("CVE-2021-44228", ids)

    def test_match_clean_sbom_passes(self):
        path = _write_sbom([{
            "name": "totally-not-real-pkg-zzz", "version": "1.0",
            "purl": "pkg:pypi/totally-not-real-pkg-zzz@1.0",
        }])
        try:
            rc, out = _capture(["db", "match", path, "--format", "json"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["finding_count"], 0)


class TestScanMatchDbFlag(unittest.TestCase):
    def test_scan_with_match_db_flag(self):
        path = _write_sbom([{
            "name": "log4j-core", "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        }])
        try:
            rc, out = _capture(["scan", path, "--match-db", "--format", "json"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)
        doc = json.loads(out)
        self.assertGreater(doc["finding_count"], 0)

    def test_vulns_with_match_db_and_no_advisory(self):
        path = _write_sbom([{
            "name": "log4j-core", "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        }])
        try:
            rc, out = _capture(["vulns", path, "--match-db", "--format", "json"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)
        doc = json.loads(out)
        ids = {f["advisory_id"] for f in doc["findings"]}
        self.assertIn("CVE-2021-44228", ids)


if __name__ == "__main__":
    unittest.main()
