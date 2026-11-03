import os
import sqlite3
import tempfile
import unittest

from vulnwatch.model import Advisory, AuditResult, Check, Finding, InventoryItem, finding_id
from vulnwatch.store import AlreadyRunning, RunLock, Store


def adv(id_, source="cvenow", title="t"):
    return Advisory(id_, (), source, title, "", None, None, False, (), None, None, False)


def finding(name):
    item = InventoryItem("npm_global", name, "1.0.0", "npm", "npm_global", "/p")
    fid = finding_id("CVE-1", item.kind, item.name, item.location)
    return Finding(fid, "CVE-1", item, "exact", False, False, False, "osv", "1.1.0", "t", None)


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.s = Store(os.path.join(self.dir, "state.db"))

    def tearDown(self):
        self.s.close()

    def test_advisory_upsert(self):
        self.s.put_advisory(adv("CVE-1", title="a"), "2026-11-03T00:00:00Z")
        self.s.put_advisory(adv("CVE-1", title="b"), "2026-11-03T00:00:01Z")
        self.assertEqual(self.s.get_advisory("cvenow", "CVE-1").title, "b")
        self.assertTrue(self.s.has_advisory("cvenow", "CVE-1"))
        self.assertFalse(self.s.has_advisory("kev", "CVE-1"))
        self.assertIsNone(self.s.get_advisory("kev", "CVE-1"))

    def test_put_advisories_batch(self):
        self.s.put_advisories([adv("CVE-1", source="osv"), adv("CVE-2", source="osv")], "x")
        self.assertEqual(sorted(a.id for a in self.s.advisories("osv")), ["CVE-1", "CVE-2"])

    def test_advisories_by_prefix(self):
        self.s.put_advisories([adv("MAL-2026-1", source="osv"), adv("GHSA-x", source="osv")], "x")
        self.assertEqual([a.id for a in self.s.advisories("osv", id_prefix="MAL-")], ["MAL-2026-1"])

    def test_advisories_by_source(self):
        self.s.put_advisory(adv("CVE-1"), "x")
        self.s.put_advisory(adv("CVE-2", source="kev"), "x")
        self.assertEqual([a.id for a in self.s.advisories("kev")], ["CVE-2"])
        self.assertEqual(sorted(a.id for a in self.s.advisories()), ["CVE-1", "CVE-2"])

    def test_cursor_roundtrip(self):
        self.s.set_cursor("x", "1")
        self.assertEqual(self.s.get_cursor("x"), "1")
        self.assertIsNone(self.s.get_cursor("y"))

    def test_pending_queue(self):
        for k in ("a", "b", "c", "a"):
            self.s.queue("cverecord", k)
        self.assertEqual(self.s.pending("cverecord", 2), ["a", "b"])
        self.s.done("cverecord", "a")
        self.assertEqual(self.s.pending("cverecord", 10), ["b", "c"])
        self.assertEqual(self.s.pending("cvenow", 10), [])

    def test_latest_findings(self):
        f1, f2 = finding("a"), finding("b")
        r1 = self.s.start_run("2026-11-02T07:30:00Z")
        self.s.save_findings(r1, [f1], {})
        self.s.finish_run(r1, "ok", {})
        r2 = self.s.start_run("2026-11-03T07:30:00Z")
        audit = AuditResult(f2.id, "1.1.0", [Check("cooldown", "pass", "")], {})
        self.s.save_findings(r2, [f2], {f2.id: audit})
        self.s.finish_run(r2, "partial", {})
        run_id, fs, audits = self.s.latest_findings()
        self.assertEqual(run_id, r2)
        self.assertEqual([f.item.name for f in fs], ["b"])
        self.assertTrue(audits[f2.id].green)
        self.assertEqual(self.s.find(f2.id), f2)
        self.assertIsNone(self.s.find(f1.id))

    def test_unfinished_run_ignored(self):
        r1 = self.s.start_run("2026-11-02T07:30:00Z")
        self.s.save_findings(r1, [finding("a")], {})
        self.s.finish_run(r1, "ok", {})
        r2 = self.s.start_run("2026-11-03T07:30:00Z")
        self.s.save_findings(r2, [finding("b")], {})
        run_id, fs, _ = self.s.latest_findings()
        self.assertEqual(run_id, r1)

    def test_ignores(self):
        self.s.add_ignore("abc", "non installato in produzione", "2026-11-03")
        self.assertEqual(self.s.ignores(), {"abc": "non installato in produzione"})

    def test_corrupt_db_raises(self):
        p = os.path.join(self.dir, "bad.db")
        with open(p, "wb") as f:
            f.write(os.urandom(4096))
        with self.assertRaises(sqlite3.DatabaseError):
            Store(p)


class RunLockTest(unittest.TestCase):
    def test_exclusive(self):
        p = os.path.join(tempfile.mkdtemp(), "run.lock")
        with RunLock(p):
            with self.assertRaises(AlreadyRunning):
                RunLock(p).__enter__()
        with RunLock(p):
            pass


if __name__ == "__main__":
    unittest.main()
