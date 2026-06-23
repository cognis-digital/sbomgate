"""Offline tests for the data-feed catalog + edge/air-gap snapshot mechanics.

These never hit the network: they validate the bundled catalog and the
cache/snapshot helpers against a temp cache directory.
"""
import json
import os
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sbomgate import datafeeds  # noqa: E402


class TestCatalog(unittest.TestCase):
    def setUp(self):
        self.cat = datafeeds.load_catalog()
        self.feeds = {f["id"]: f for f in self.cat.get("feeds", [])}

    def test_catalog_loads(self):
        self.assertGreater(len(self.feeds), 10)

    def test_relevant_feeds_present(self):
        for fid in ("cisa-kev", "epss", "osv"):
            self.assertIn(fid, self.feeds)

    def test_feeds_are_keyless_and_real_hosts(self):
        kev = self.feeds["cisa-kev"]
        self.assertTrue(kev.get("keyless"))
        self.assertIn("cisa.gov", kev["url"])
        self.assertIn("first.org", self.feeds["epss"]["url"])
        self.assertIn("osv.dev", self.feeds["osv"]["url"])

    def test_every_feed_has_url_and_id(self):
        for f in self.cat["feeds"]:
            self.assertTrue(f.get("id"))
            self.assertTrue(f.get("url", "").startswith("http"))

    def test_bulk_harvest_helper_exists(self):
        # edge corpus refresh from NVD/GHSA
        self.assertTrue(hasattr(datafeeds, "harvest_cves"))


class TestCacheAndSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Save and restore any pre-existing cache path so we don't clobber the
        # fixture cache that other test modules (e.g. test_feeds) set globally.
        self._prev = os.environ.get("COGNIS_FEEDS_CACHE")
        os.environ["COGNIS_FEEDS_CACHE"] = self.tmp

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("COGNIS_FEEDS_CACHE", None)
        else:
            os.environ["COGNIS_FEEDS_CACHE"] = self._prev

    def test_cache_dir_honors_env(self):
        self.assertEqual(str(datafeeds.cache_dir()), self.tmp)

    def test_uncached_age_is_none(self):
        self.assertIsNone(datafeeds.cached_age_hours("cisa-kev"))

    def test_snapshot_export_import_round_trip(self):
        # seed a fake cached feed
        p = datafeeds.cache_dir() / "cisa-kev.data"
        p.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
        meta = datafeeds.cache_dir() / "cisa-kev.meta.json"
        meta.write_text(json.dumps({"id": "cisa-kev"}), encoding="utf-8")

        tar_path = os.path.join(self.tmp, "snap.tar.gz")
        datafeeds.snapshot_export(tar_path)
        self.assertTrue(os.path.isfile(tar_path))
        with tarfile.open(tar_path) as tf:
            names = tf.getnames()
        self.assertTrue(any("cisa-kev" in n for n in names))

        # wipe + reimport
        p.unlink()
        datafeeds.snapshot_import(tar_path)
        self.assertTrue((datafeeds.cache_dir() / "cisa-kev.data").exists())


if __name__ == "__main__":
    unittest.main()
