import io
import json
import os
import tempfile
import unittest
import zipfile

from tests.helpers import NOW, json_bytes, load_fixture
from vulnwatch.model import VersionRange as VR
from vulnwatch.net import FakeTransport, Fetcher, FetchError, Response
from vulnwatch.sources import osv
from vulnwatch.store import Store

HOSTS = ("osv-vulnerabilities.storage.googleapis.com",)
B = osv.OSV_BASE


def rec(id_, modified, name="pkg", events=None):
    return {
        "id": id_,
        "modified": modified,
        "summary": "s " + id_,
        "details": "d" * 50,
        "aliases": ["CVE-2026-1"],
        "affected": [{
            "package": {"ecosystem": "npm", "name": name},
            "ranges": [{"type": "SEMVER", "events": events or [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
        }],
    }


def zip_bytes(records, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in records:
            z.writestr(r["id"] + ".json", json.dumps(r))
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


class ParseTest(unittest.TestCase):
    def test_npm_fixture(self):
        a = osv.parse_osv(load_fixture("osv/record_npm.json"))
        self.assertEqual(a.source, "osv")
        self.assertEqual(a.id, "GHSA-r4q5-vmmm-2653")
        self.assertIn("CVE-2026-40895", a.aliases)
        self.assertEqual((a.affected[0].ecosystem, a.affected[0].package), ("npm", "follow-redirects"))
        self.assertEqual(a.affected[0].ranges, (VR("0", "1.16.0", None),))
        self.assertEqual(a.description, "")
        self.assertIs(a.malicious, False)

    def test_pypi_fixture_versions(self):
        a = osv.parse_osv(load_fixture("osv/record_pypi.json"))
        self.assertEqual(a.affected[0].ecosystem, "PyPI")
        self.assertTrue(len(a.affected[0].versions) > 0)

    def test_multiple_intervals(self):
        ev = [{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}, {"fixed": "2.5.0"}]
        a = osv.parse_osv(rec("GHSA-a", "2026-11-01T00:00:00Z", events=ev))
        self.assertEqual(a.affected[0].ranges, (VR("0", "1.0.0", None), VR("2.0.0", "2.5.0", None)))

    def test_last_affected_and_open_end(self):
        ev = [{"introduced": "1.0.0"}, {"last_affected": "1.2.0"}, {"introduced": "3.0.0"}]
        a = osv.parse_osv(rec("GHSA-b", "2026-11-01T00:00:00Z", events=ev))
        self.assertEqual(a.affected[0].ranges, (VR("1.0.0", None, "1.2.0"), VR("3.0.0", None, None)))

    def test_git_ranges_ignored(self):
        r = rec("GHSA-c", "2026-11-01T00:00:00Z")
        r["affected"][0]["ranges"] = [{"type": "GIT", "events": [{"introduced": "abc"}]}]
        self.assertEqual(osv.parse_osv(r).affected[0].ranges, ())

    def test_mal_fixture(self):
        a = osv.parse_osv(load_fixture("osv/record_mal.json"))
        self.assertIs(a.malicious, True)
        self.assertTrue(len(a.affected[0].versions) > 0)

    def test_hostile_ids(self):
        with self.assertRaises(ValueError):
            osv.parse_osv(rec("GHSA-a](https://evil)", "2026-11-01T00:00:00Z"))
        r = rec("GHSA-ok", "2026-11-01T00:00:00Z")
        r["aliases"] = ["CVE-2026-1000", "[x](https://evil)"]
        self.assertEqual(osv.parse_osv(r).aliases, ("CVE-2026-1000",))

    def test_malformed(self):
        with self.assertRaises(ValueError):
            osv.parse_osv({"id": "X", "affected": [{"package": "npm"}]})


class TimestampKeyTest(unittest.TestCase):
    def test_variable_fraction_digits(self):
        self.assertLess(osv.ts_key("2026-11-03T06:45:06.81948731Z"), osv.ts_key("2026-11-03T06:45:06.819487311Z"))
        self.assertEqual(osv.ts_key("2026-11-03T06:45:06.8Z"), osv.ts_key("2026-11-03T06:45:06.800000000Z"))
        self.assertLess(osv.ts_key("2026-11-03T06:45:06Z"), osv.ts_key("2026-11-03T06:45:06.1Z"))


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.tmp, "s.db"))

    def fetcher(self, routes):
        return Fetcher(FakeTransport(routes), HOSTS, sleep=lambda x: None)

    def sync(self, f, limit=100):
        return osv.sync(f, self.store, NOW, ["npm"], self.tmp, limit=limit, zip_max_bytes=10_000_000)

    def test_bootstrap_from_zip(self):
        z = zip_bytes([rec("GHSA-1", "2026-11-01T00:00:00.5Z"), rec("GHSA-2", "2026-11-02T00:00:00Z")])
        stats = self.sync(self.fetcher({B + "/npm/all.zip": Response(200, {}, z)}))
        self.assertEqual(stats.stored, 2)
        self.assertEqual(self.store.get_cursor("osv_npm"), "2026-11-02T00:00:00Z")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "osv-npm-all.zip")))

    def test_zip_member_too_large_skipped(self):
        big = json.dumps(rec("GHSA-big", "2026-11-03T00:00:00Z")) + " " * (osv.MAX_MEMBER_BYTES + 1)
        z = zip_bytes([rec("GHSA-1", "2026-11-01T00:00:00Z")], extra={"GHSA-big.json": big})
        stats = self.sync(self.fetcher({B + "/npm/all.zip": Response(200, {}, z)}))
        self.assertEqual(stats.stored, 1)
        self.assertEqual(len(stats.errors), 1)

    def _csv(self, rows):
        return ("\n".join("%s,%s" % r for r in rows) + "\n").encode()

    def _incremental_routes(self, rows):
        routes = {B + "/npm/modified_id.csv": Response(200, {}, self._csv(rows))}
        for ts, id_ in rows:
            routes[B + "/npm/" + id_ + ".json"] = Response(200, {}, json_bytes(rec(id_, ts)))
        return routes

    def test_incremental_ascending(self):
        self.store.set_cursor("osv_npm", "2026-11-01T00:00:00Z")
        rows = [("2026-11-03T03:00:00Z", "GHSA-c"), ("2026-11-02T02:00:00Z", "GHSA-b"),
                ("2026-11-01T01:00:00Z", "GHSA-a"), ("2026-11-01T00:00:00Z", "GHSA-old"),
                ("2026-10-30T00:00:00Z", "GHSA-older")]
        f = self.fetcher(self._incremental_routes(rows))
        self.sync(f)
        fetched = [u.rsplit("/", 1)[1] for u in f.request_log[1:]]
        self.assertEqual(fetched, ["GHSA-a.json", "GHSA-b.json", "GHSA-c.json"])
        self.assertEqual(self.store.get_cursor("osv_npm"), "2026-11-03T03:00:00Z")

    def test_incremental_limit_is_monotonic(self):
        self.store.set_cursor("osv_npm", "2026-11-01T00:00:00Z")
        rows = [("2026-11-03T03:00:00Z", "GHSA-c"), ("2026-11-02T02:00:00Z", "GHSA-b"),
                ("2026-11-01T01:00:00Z", "GHSA-a")]
        self.sync(self.fetcher(self._incremental_routes(rows)), limit=2)
        self.assertEqual(self.store.get_cursor("osv_npm"), "2026-11-02T02:00:00Z")
        f = self.fetcher(self._incremental_routes(rows))
        self.sync(f, limit=2)
        self.assertEqual([u.rsplit("/", 1)[1] for u in f.request_log[1:]], ["GHSA-c.json"])

    def test_equal_timestamps_not_split(self):
        self.store.set_cursor("osv_npm", "2026-11-01T00:00:00Z")
        rows = [("2026-11-02T00:00:00Z", "GHSA-y"), ("2026-11-02T00:00:00Z", "GHSA-x"),
                ("2026-11-01T01:00:00Z", "GHSA-a")]
        stats = self.sync(self.fetcher(self._incremental_routes(rows)), limit=2)
        self.assertEqual(stats.stored, 3)

    def test_network_error_stops_and_keeps_cursor(self):
        self.store.set_cursor("osv_npm", "2026-11-01T00:00:00Z")
        rows = [("2026-11-02T02:00:00Z", "GHSA-b"), ("2026-11-01T01:00:00Z", "GHSA-a")]
        routes = self._incremental_routes(rows)
        routes[B + "/npm/GHSA-a.json"] = FetchError("rete giù")
        stats = self.sync(self.fetcher(routes))
        self.assertEqual(stats.stored, 0)
        self.assertEqual(self.store.get_cursor("osv_npm"), "2026-11-01T00:00:00Z")

    def test_rejects_bad_ecosystem_name(self):
        stats = osv.sync(self.fetcher({}), self.store, NOW, ["../x"], self.tmp, limit=10, zip_max_bytes=10)
        self.assertEqual(stats.stored, 0)
        self.assertEqual(len(stats.errors), 1)


if __name__ == "__main__":
    unittest.main()
