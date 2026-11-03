import os
import tempfile
import unittest

from tests.helpers import NOW, json_bytes, load_fixture
from vulnwatch.model import VersionRange as VR
from vulnwatch.net import FakeTransport, Fetcher, Response
from vulnwatch.sources import cverecord
from vulnwatch.store import Store

HOSTS = ("raw.githubusercontent.com",)


def synthetic(cna_score=7.5, adp_score=9.8):
    return {
        "cveMetadata": {"cveId": "CVE-2026-1000", "state": "PUBLISHED", "datePublished": "2026-10-01T00:00:00Z"},
        "containers": {
            "cna": {
                "title": "titolo",
                "descriptions": [{"lang": "en", "value": "descrizione"}],
                "metrics": [{"cvssV3_1": {"baseScore": cna_score}}],
                "affected": [{
                    "vendor": "Acme",
                    "product": "Widget",
                    "versions": [
                        {"version": "0", "lessThan": "2.0", "status": "affected"},
                        {"version": "3.1", "status": "affected"},
                        {"version": "unspecified", "lessThanOrEqual": "4.0", "status": "affected"},
                        {"version": "5.0", "status": "unaffected"},
                    ],
                }],
            },
            "adp": [{"metrics": [{"cvssV3_1": {"baseScore": adp_score}}]}],
        },
    }


class RecordUrlTest(unittest.TestCase):
    def test_bucket(self):
        self.assertTrue(cverecord.record_url("CVE-2026-120534").endswith("/cves/2026/120xxx/CVE-2026-120534.json"))
        self.assertTrue(cverecord.record_url("CVE-2024-0001").endswith("/cves/2024/0xxx/CVE-2024-0001.json"))
        self.assertTrue(cverecord.record_url("CVE-2026-4052").startswith(
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/4xxx/"))

    def test_rejects_injection(self):
        for bad in ("CVE-2026-1/../../x", "../x", "CVE-26-1", "GHSA-aaaa-bbbb-cccc"):
            with self.assertRaises(ValueError):
                cverecord.record_url(bad)


class ParseRecordTest(unittest.TestCase):
    def test_ranges_and_versions(self):
        a = cverecord.parse_record(synthetic())
        self.assertEqual(a.source, "cverecord")
        self.assertEqual(a.affected[0].ranges, (VR(None, "2.0", None), VR(None, None, "4.0")))
        self.assertEqual(a.affected[0].versions, ("3.1",))
        self.assertEqual((a.affected[0].vendor, a.affected[0].product), ("Acme", "Widget"))

    def test_cvss_max_and_critical(self):
        a = cverecord.parse_record(synthetic())
        self.assertEqual(a.cvss, 9.8)
        self.assertEqual(a.severity, "critical")
        b = cverecord.parse_record(synthetic(5.0, 6.0))
        self.assertEqual(b.cvss, 6.0)
        self.assertIsNone(b.severity)

    def test_fixture(self):
        a = cverecord.parse_record(load_fixture("cverecord/record.json"))
        self.assertEqual(a.id, "CVE-2026-4052")
        self.assertEqual(a.cvss, 9.8)
        self.assertIn("4.6.0", a.affected[0].versions)

    def test_malformed_raises(self):
        with self.assertRaises(ValueError):
            cverecord.parse_record({"containers": {}})


class SyncTest(unittest.TestCase):
    def test_sync_pending(self):
        s = Store(os.path.join(tempfile.mkdtemp(), "s.db"))
        for k in ("CVE-2026-1000", "CVE-2026-2000", "CVE-2026-3000"):
            s.queue("cverecord", k)
        t = FakeTransport({
            cverecord.DELTA_URL: Response(200, {}, b"[]"),
            cverecord.record_url("CVE-2026-1000"): Response(200, {}, json_bytes(synthetic())),
            cverecord.record_url("CVE-2026-3000"): Response(500, {}, b""),
        })
        stats = cverecord.sync(Fetcher(t, HOSTS, sleep=lambda x: None), s, NOW, limit=10)
        self.assertTrue(s.has_advisory("cverecord", "CVE-2026-1000"))
        self.assertEqual(stats.stored, 1)
        self.assertEqual(len(stats.errors), 2)
        self.assertEqual(stats.failed, 1)
        self.assertEqual(s.pending("cverecord", 10), ["CVE-2026-3000"])


class DeltaTest(unittest.TestCase):
    def test_delta_requeues_changed_records_only_from_archive(self):
        s = Store(os.path.join(tempfile.mkdtemp(), "s.db"))
        s.put_advisory(cverecord.parse_record(synthetic(7.0, 7.0)), "x")
        delta = [{"fetchTime": "2026-11-03T09:00:00.000Z", "new": [{"cveId": "CVE-2026-5555"}],
                  "updated": [{"cveId": "CVE-2026-1000"}, {"cveId": "../evil"}]},
                 {"fetchTime": "2026-11-02T09:00:00.000Z", "updated": [{"cveId": "CVE-2026-1000"}]}]
        f = Fetcher(FakeTransport({
            cverecord.DELTA_URL: Response(200, {}, json_bytes(delta)),
            cverecord.record_url("CVE-2026-1000"): Response(200, {}, json_bytes(synthetic(5.0, 9.9))),
        }), HOSTS, sleep=lambda x: None)
        stats = cverecord.sync(f, s, NOW, limit=10)
        self.assertEqual(s.get_advisory("cverecord", "CVE-2026-1000").cvss, 9.9)
        self.assertEqual(s.get_cursor("cverecord_delta"), "2026-11-03T09:00:00.000Z")
        self.assertEqual(s.pending("cverecord", 10), [])
        self.assertFalse(stats.incomplete)

    def test_delta_failure_marks_incomplete(self):
        s = Store(os.path.join(tempfile.mkdtemp(), "s.db"))
        f = Fetcher(FakeTransport({cverecord.DELTA_URL: Response(500, {}, b"")}), HOSTS, sleep=lambda x: None)
        self.assertTrue(cverecord.sync(f, s, NOW, limit=10).incomplete)


if __name__ == "__main__":
    unittest.main()
