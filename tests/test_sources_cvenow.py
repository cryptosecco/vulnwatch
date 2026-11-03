import copy
import os
import tempfile
import unittest
from urllib.parse import quote

from tests.helpers import NOW, json_bytes, load_fixture
from vulnwatch.net import FakeTransport, Fetcher, Response
from vulnwatch.sources import cvenow
from vulnwatch.store import Store

BLOB = "https://f9gkulwameaj0boi.public.blob.vercel-storage.com/public/entries/"
HOSTS = ("cve.now", "f9gkulwameaj0boi.public.blob.vercel-storage.com")


def entry(id_):
    e = copy.deepcopy(load_fixture("cvenow/entry.json"))
    e["id"] = id_
    return e


class ParseEntryTest(unittest.TestCase):
    def test_fixture(self):
        a = cvenow.parse_entry(load_fixture("cvenow/entry.json"))
        self.assertEqual(a.id, "CVE-2026-4052")
        self.assertEqual(a.source, "cvenow")
        self.assertEqual(a.cvss, 9.8)
        self.assertIs(a.kev, False)
        self.assertEqual(a.affected[0].vendor, "WSO2")
        self.assertIn("4.6.0", a.affected[0].versions)

    def test_ecosystem_fixture(self):
        a = cvenow.parse_entry(load_fixture("cvenow/entry_ecosystem.json"))
        eco = a.affected[0]
        self.assertEqual((eco.ecosystem, eco.package), ("npm", "signalk-server"))
        self.assertEqual(eco.ranges[0].introduced, "2.0.0")
        self.assertEqual(eco.ranges[0].fixed, "2.34.0")

    def test_hostile_ids(self):
        with self.assertRaises(ValueError):
            cvenow.parse_entry({"id": "CVE-2026-1](https://evil.example/x)"})
        a = cvenow.parse_entry({"id": "CVE-2026-1000", "aliases": ["GHSA-aaaa-bbbb-cccc", "[x](https://evil)"]})
        self.assertEqual(a.aliases, ("GHSA-aaaa-bbbb-cccc",))

    def test_malformed_raises(self):
        with self.assertRaises(ValueError):
            cvenow.parse_entry({"id": 3})
        with self.assertRaises(ValueError):
            cvenow.parse_entry({"id": "CVE-2026-1", "affected": [{"ranges": [{"fixed": {"x": 1}}]}]})


class DetailUrlTest(unittest.TestCase):
    def test_accepts_ids(self):
        self.assertEqual(cvenow.detail_url("CVE-2026-4052"), "https://cve.now/api/v1/entries/CVE-2026-4052")
        cvenow.detail_url("GHSA-4XM8-RG9H-JHQ2")
        cvenow.detail_url("GHSA-4xm8-rg9h-jhq2")

    def test_rejects(self):
        for bad in ("../x", "CVE-2026-1/../x", "a b", ""):
            with self.assertRaises(ValueError):
                cvenow.detail_url(bad)


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), "s.db"))
        p1 = {"entries": [
            {"id": "CVE-2026-3", "publishedAt": "2026-11-03T08:00:00.000Z"},
            {"id": "CVE-2026-2", "publishedAt": "2026-11-02T08:00:00.000Z"},
        ], "nextCursor": "c/2"}
        p2 = {"entries": [{"id": "CVE-2026-1", "publishedAt": "2026-11-01T08:00:00.000Z"}], "nextCursor": None}
        self.p1 = cvenow.LIST_URL
        self.p2 = cvenow.LIST_URL + "&cursor=" + quote("c/2", safe="")
        routes = {self.p1: Response(200, {}, json_bytes(p1)), self.p2: Response(200, {}, json_bytes(p2))}
        for i in ("CVE-2026-1", "CVE-2026-2", "CVE-2026-3"):
            routes[cvenow.detail_url(i)] = Response(302, {"location": BLOB + i + ".json"}, b"")
            routes[BLOB + i + ".json"] = Response(200, {}, json_bytes(entry(i)))
        self.t = FakeTransport(routes)
        self.f = Fetcher(self.t, HOSTS, sleep=lambda x: None)

    def test_uniform_fetch_in_list_order(self):
        stats = cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        d = lambda i: [cvenow.detail_url(i), BLOB + i + ".json"]
        self.assertEqual(self.f.request_log, [self.p1, self.p2] + d("CVE-2026-3") + d("CVE-2026-2") + d("CVE-2026-1"))
        self.assertEqual(stats.stored, 3)
        self.assertEqual(self.store.get_cursor("cvenow_pub_since"), "2026-11-03T08:00:00.000Z")
        self.assertIn("CVE-2026-3", self.store.pending("cverecord", 10))

    def test_daily_overlap_relists_but_fetches_only_new(self):
        self.store.set_cursor("cvenow_pub_since", "2026-11-02T08:00:00.000Z")
        for i in ("CVE-2026-2", "CVE-2026-1"):
            self.store.put_advisory(cvenow.parse_entry(entry(i)), "x")
        cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        self.assertEqual(self.f.request_log,
                         [self.p1, self.p2, cvenow.detail_url("CVE-2026-3"), BLOB + "CVE-2026-3.json"])

    def test_overlap_catches_late_published_entry(self):
        self.store.set_cursor("cvenow_pub_since", "2026-11-03T08:00:00.000Z")
        cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        self.assertTrue(self.store.has_advisory("cvenow", "CVE-2026-2"))

    def test_stops_on_publication_not_import_date(self):
        old = {"entries": [{"id": "CVE-2026-1", "firstSeenAt": "2026-11-03T09:00:00.000Z",
                            "publishedAt": "2026-06-01T00:00:00.000Z"}], "nextCursor": "c/3"}
        self.t.routes[self.p2] = Response(200, {}, json_bytes(old))
        stats = cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        self.assertFalse(stats.incomplete)
        self.assertFalse(self.store.has_advisory("cvenow", "CVE-2026-1"))
        self.assertEqual(len([u for u in self.f.request_log if u.startswith(cvenow.LIST_URL)]), 2)

    def test_backfill_window(self):
        cvenow.sync(self.f, self.store, NOW, backfill_days=1, limit=100)
        self.assertTrue(self.store.has_advisory("cvenow", "CVE-2026-3"))
        self.assertFalse(self.store.has_advisory("cvenow", "CVE-2026-1"))

    def test_rate_limited_listing_keeps_progress(self):
        self.t.routes[self.p2] = Response(403, {}, b"")
        stats = cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        self.assertTrue(stats.incomplete)
        self.assertFalse(self.store.get_cursor("cvenow_pub_since"))
        self.assertEqual(self.store.get_cursor("cvenow_pub_top"), "2026-11-03T08:00:00.000Z")
        self.assertEqual(self.store.get_cursor("cvenow_pub_resume"), "c/2")
        self.assertTrue(self.store.has_advisory("cvenow", "CVE-2026-3"))
        self.assertFalse(self.store.has_advisory("cvenow", "CVE-2026-1"))

    def test_resume_completes_descent(self):
        p2_ok = self.t.routes[self.p2]
        self.t.routes[self.p2] = Response(403, {}, b"")
        cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        self.t.routes[self.p2] = p2_ok
        self.f.request_log.clear()
        stats = cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        self.assertFalse(stats.incomplete)
        self.assertTrue(self.store.has_advisory("cvenow", "CVE-2026-1"))
        self.assertEqual(self.store.get_cursor("cvenow_pub_since"), "2026-11-03T08:00:00.000Z")
        self.assertFalse(self.store.get_cursor("cvenow_pub_top"))
        self.assertFalse(self.store.get_cursor("cvenow_pub_resume"))
        self.assertEqual(self.f.request_log[:2], [self.p1, self.p2])

    def test_first_page_failure_raises(self):
        self.t.routes[self.p1] = Response(500, {}, b"")
        with self.assertRaises(Exception):
            cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)

    def test_detail_rate_limit_stops_details(self):
        self.t.routes[cvenow.detail_url("CVE-2026-3")] = Response(429, {}, b"")
        stats = cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=100)
        self.assertTrue(stats.incomplete)
        self.assertEqual(stats.stored, 0)
        self.assertEqual(self.store.pending("cvenow", 10), ["CVE-2026-3", "CVE-2026-2", "CVE-2026-1"])

    def test_limit_keeps_rest_pending(self):
        stats = cvenow.sync(self.f, self.store, NOW, backfill_days=90, limit=1)
        self.assertEqual(stats.stored, 1)
        self.assertEqual(self.store.pending("cvenow", 10), ["CVE-2026-2", "CVE-2026-1"])


if __name__ == "__main__":
    unittest.main()
