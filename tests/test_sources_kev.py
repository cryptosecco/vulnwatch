import os
import tempfile
import unittest

from tests.helpers import NOW, json_bytes, load_fixture
from vulnwatch.net import FakeTransport, Fetcher, Response
from vulnwatch.sources import kev
from vulnwatch.store import Store

HOSTS = ("www.cisa.gov",)


class KevTest(unittest.TestCase):
    def test_parse_fixture(self):
        advs = kev.parse_catalog(load_fixture("kev/catalog_small.json"))
        self.assertEqual([a.id for a in advs], ["CVE-2026-118527", "CVE-2026-111357", "CVE-2026-97229"])
        self.assertTrue(all(a.kev and a.source == "kev" for a in advs))
        self.assertEqual(advs[0].affected[0].vendor, "Ivanti")
        self.assertEqual(advs[0].affected[0].product, "Connect Secure")
        self.assertEqual(advs[0].published, "2026-10-30")

    def test_malformed_entry_raises(self):
        with self.assertRaises(ValueError):
            kev.parse_catalog({"vulnerabilities": [{"cveID": 5}]})
        with self.assertRaises(ValueError):
            kev.parse_catalog({"vulnerabilities": [{"cveID": "CVE-2026-1](https://evil)"}]})

    def test_sync_stores_and_queues_cverecord(self):
        t = FakeTransport({kev.KEV_URL: Response(200, {}, json_bytes(load_fixture("kev/catalog_small.json")))})
        s = Store(os.path.join(tempfile.mkdtemp(), "s.db"))
        stats = kev.sync(Fetcher(t, HOSTS, sleep=lambda x: None), s, NOW)
        self.assertEqual(stats.stored, 3)
        self.assertEqual(stats.errors, [])
        self.assertEqual(s.pending("cverecord", 10), ["CVE-2026-118527", "CVE-2026-111357", "CVE-2026-97229"])
        self.assertTrue(s.has_advisory("kev", "CVE-2026-97229"))

    def test_sync_network_error_raises(self):
        t = FakeTransport({kev.KEV_URL: Response(500, {}, b"")})
        s = Store(os.path.join(tempfile.mkdtemp(), "s.db"))
        with self.assertRaises(Exception):
            kev.sync(Fetcher(t, HOSTS, sleep=lambda x: None), s, NOW)


if __name__ == "__main__":
    unittest.main()
