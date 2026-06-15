"""Tests covering hardened error/edge paths added in the robustness pass.

No network. Pure stdlib + unittest.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sbomgate.core import (  # noqa: E402
    diff_sboms,
    gate,
    load_advisories,
    load_sbom,
    match_vulnerabilities,
    parse_sbom,
)
from sbomgate.cli import main  # noqa: E402

DEMO = os.path.join(ROOT, "demos", "01-basic")
NEW = os.path.join(DEMO, "sbom-new.json")
ADV = os.path.join(DEMO, "advisories.json")


class TestLoadSbomErrors(unittest.TestCase):
    """load_sbom should raise clear errors for bad inputs."""

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_sbom("/no/such/path/sbom.json")

    def test_malformed_json_raises_json_decode_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write("{not valid json")
            name = f.name
        try:
            with self.assertRaises(json.JSONDecodeError):
                load_sbom(name)
        finally:
            os.unlink(name)

    def test_unrecognised_structure_raises_value_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"bomFormat": "Unknown", "metadata": {}}, f)
            name = f.name
        try:
            with self.assertRaises(ValueError):
                load_sbom(name)
        finally:
            os.unlink(name)

    def test_empty_components_array_returns_empty_list(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"components": []}, f)
            name = f.name
        try:
            result = load_sbom(name)
            self.assertEqual(result, [])
        finally:
            os.unlink(name)

    def test_bare_empty_list_returns_empty_list(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump([], f)
            name = f.name
        try:
            result = load_sbom(name)
            self.assertEqual(result, [])
        finally:
            os.unlink(name)


class TestLoadAdvisoriesErrors(unittest.TestCase):
    """load_advisories should raise clear errors for bad inputs."""

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_advisories("/no/such/path/advisories.json")

    def test_malformed_json_raises_json_decode_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write("[{broken")
            name = f.name
        try:
            with self.assertRaises(json.JSONDecodeError):
                load_advisories(name)
        finally:
            os.unlink(name)

    def test_wrong_top_level_type_raises_value_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump("just a string", f)
            name = f.name
        try:
            with self.assertRaises(ValueError):
                load_advisories(name)
        finally:
            os.unlink(name)

    def test_advisories_wrapper_object_is_accepted(self):
        feed = {"advisories": [{"id": "X", "name": "foo", "severity": "low", "affected": []}]}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(feed, f)
            name = f.name
        try:
            result = load_advisories(name)
            self.assertEqual(len(result), 1)
        finally:
            os.unlink(name)


class TestParseSbomEdgeCases(unittest.TestCase):
    """parse_sbom handles unusual but valid inputs gracefully."""

    def test_components_with_no_name_are_skipped(self):
        data = {"components": [{"version": "1.0"}, {"name": "valid", "version": "2.0"}]}
        result = parse_sbom(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "valid")

    def test_spdx_packages_key_accepted(self):
        data = {"packages": [{"name": "spdx-pkg", "versionInfo": "3.0"}]}
        result = parse_sbom(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].version, "3.0")

    def test_bare_list_accepted(self):
        data = [{"name": "bare-pkg", "version": "0.1"}]
        result = parse_sbom(data)
        self.assertEqual(len(result), 1)

    def test_wrong_type_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_sbom("just a string")

    def test_wrong_type_integer_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_sbom(42)


class TestGateValidation(unittest.TestCase):
    """gate() should reject invalid fail_on values."""

    def test_invalid_fail_on_raises_value_error(self):
        with self.assertRaises(ValueError):
            gate([], fail_on="bogus")

    def test_valid_fail_on_values_are_accepted(self):
        for level in ("critical", "high", "medium", "low"):
            result = gate([], fail_on=level)
            self.assertFalse(result)  # no findings -> never fails


class TestDiffEdgeCases(unittest.TestCase):
    """diff_sboms handles empty collections."""

    def test_both_empty(self):
        result = diff_sboms([], [])
        self.assertEqual(result.old_count, 0)
        self.assertEqual(result.new_count, 0)
        self.assertEqual(result.findings, [])

    def test_empty_old_all_added(self):
        new_comps = parse_sbom([{"name": "pkg-a", "version": "1.0"}])
        result = diff_sboms([], new_comps)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].kind, "added")

    def test_empty_new_all_removed(self):
        old_comps = parse_sbom([{"name": "pkg-b", "version": "1.0"}])
        result = diff_sboms(old_comps, [])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].kind, "removed")


class TestMatchVulnerabilitiesEdgeCases(unittest.TestCase):
    """match_vulnerabilities handles unusual advisory data."""

    def test_no_components(self):
        findings = match_vulnerabilities([], [{"name": "foo", "severity": "high", "affected": ["<1.0"]}])
        self.assertEqual(findings, [])

    def test_no_advisories(self):
        comps = parse_sbom([{"name": "foo", "version": "0.5"}])
        findings = match_vulnerabilities(comps, [])
        self.assertEqual(findings, [])

    def test_non_string_constraint_is_skipped(self):
        """A constraint entry that is not a string should not crash."""
        comps = parse_sbom([{"name": "foo", "version": "0.5"}])
        advisories = [{"name": "foo", "severity": "high", "affected": [None, 42, "<1.0"]}]
        findings = match_vulnerabilities(comps, advisories)
        # "<1.0" matches 0.5, so we expect one finding
        self.assertEqual(len(findings), 1)

    def test_component_without_version_not_matched(self):
        comps = parse_sbom([{"name": "foo"}])
        advisories = [{"name": "foo", "severity": "high", "affected": ["<1.0"]}]
        findings = match_vulnerabilities(comps, advisories)
        self.assertEqual(findings, [])


class TestCLIHardenedErrors(unittest.TestCase):
    """CLI error paths introduced by the hardening pass."""

    def test_missing_sbom_returns_2(self):
        rc = main(["scan", "/no/such/sbom.json"])
        self.assertEqual(rc, 2)

    def test_malformed_sbom_returns_2(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write("{not valid")
            name = f.name
        try:
            rc = main(["scan", name])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(name)

    def test_missing_advisory_file_returns_2(self):
        rc = main(["scan", NEW, "--advisories", "/no/such/advisories.json"])
        self.assertEqual(rc, 2)

    def test_invalid_fail_on_exits_2(self):
        # argparse enforces the choices constraint and calls sys.exit(2)
        with self.assertRaises(SystemExit) as ctx:
            main(["scan", NEW, "--fail-on", "bogus"])
        self.assertEqual(ctx.exception.code, 2)

    def test_diff_missing_old_returns_2(self):
        rc = main(["diff", "/no/old.json", NEW])
        self.assertEqual(rc, 2)

    def test_vulns_missing_sbom_returns_2(self):
        rc = main(["vulns", "/no/sbom.json", ADV])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
