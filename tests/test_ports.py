"""Tests for the polyglot ports (JS / Go / Rust).

The JS port is smoke-run directly when Node is available (offline). For every
port we assert the source + manifest + CI job exist so the ports are real and
verifiable rather than vaporware. No network.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORTS = os.path.join(ROOT, "ports")
FIX = os.path.join(PORTS, "fixtures")


class TestPortSourcesExist(unittest.TestCase):
    def test_js_port_files(self):
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "javascript", "index.js")))
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "javascript", "test.mjs")))
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "javascript", "package.json")))

    def test_go_port_files(self):
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "go", "main.go")))
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "go", "main_test.go")))
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "go", "go.mod")))

    def test_rust_port_files(self):
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "rust", "src", "main.rs")))
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "rust", "src", "json.rs")))
        self.assertTrue(os.path.isfile(os.path.join(PORTS, "rust", "Cargo.toml")))

    def test_shared_fixtures_exist(self):
        self.assertTrue(os.path.isfile(os.path.join(FIX, "sbom-old.json")))
        self.assertTrue(os.path.isfile(os.path.join(FIX, "sbom-new.json")))

    def test_ports_ci_workflow_exists(self):
        ci = os.path.join(ROOT, ".github", "workflows", "ports.yml")
        self.assertTrue(os.path.isfile(ci))
        text = open(ci, encoding="utf-8").read()
        for job in ("javascript:", "go:", "rust:"):
            self.assertIn(job, text)


class TestRustPortHasTests(unittest.TestCase):
    def test_rust_has_cfg_test(self):
        src = open(os.path.join(PORTS, "rust", "src", "main.rs"), encoding="utf-8").read()
        self.assertIn("#[cfg(test)]", src)
        self.assertIn("fn diff_detects_added_removed_and_version", src)


@unittest.skipIf(shutil.which("node") is None, "node not installed")
class TestJsPortRuns(unittest.TestCase):
    JS = os.path.join(PORTS, "javascript")

    def test_js_smoke_test_passes(self):
        r = subprocess.run([shutil.which("node"), "test.mjs"], cwd=self.JS,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("checks passed", r.stdout)

    def test_js_diff_exit_and_shape(self):
        r = subprocess.run(
            [shutil.which("node"), "index.js", "diff",
             os.path.join(FIX, "sbom-old.json"), os.path.join(FIX, "sbom-new.json")],
            cwd=self.JS, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)  # maintainer-change is high -> gate fail
        doc = json.loads(r.stdout)
        self.assertEqual(doc["tool"], "sbomgate")
        self.assertEqual(doc["gate"], "fail")
        kinds = {f["kind"] for f in doc["findings"]}
        self.assertIn("maintainer-change", kinds)
        self.assertIn("added", kinds)


if __name__ == "__main__":
    unittest.main()
