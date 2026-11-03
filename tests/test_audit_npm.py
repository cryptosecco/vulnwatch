import copy
import unittest
from datetime import timedelta

from tests.helpers import NOW, json_bytes
from vulnwatch.audit import cooldown_check
from vulnwatch.audit.npm import REGISTRY, audit_npm_global, packument_url, select_candidate
from vulnwatch.model import InventoryItem
from vulnwatch.net import FakeTransport, Fetcher, Response

ITEM = InventoryItem("npm_global", "pkg", "1.0.0", "npm", "npm_global", "/p")
NODE = "22.23.4"


def ts(hours_ago):
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def version(v, integrity):
    return {
        "version": v,
        "maintainers": [{"name": "alice"}, {"name": "bob"}],
        "_npmUser": {"name": "alice"},
        "scripts": {"test": "x"},
        "dependencies": {"a": "^1.0.0"},
        "dist": {"integrity": integrity, "tarball": "https://registry.npmjs.org/pkg/-/pkg-%s.tgz" % v},
    }


def base():
    return {
        "name": "pkg",
        "dist-tags": {"latest": "1.1.0"},
        "time": {"1.0.0": ts(24 * 300), "1.1.0": ts(72)},
        "versions": {"1.0.0": version("1.0.0", "sha512-old"), "1.1.0": version("1.1.0", "sha512-new")},
    }


def run(pk, fixed="1.1.0", accept_fresh=False, malicious=False, item=ITEM, status=200):
    t = FakeTransport({packument_url(item.name): Response(status, {}, json_bytes(pk))})
    f = Fetcher(t, ("registry.npmjs.org",), sleep=lambda x: None)
    return audit_npm_global(item, fixed, f, NOW, 48, NODE, lambda n, v: malicious, "fid", accept_fresh=accept_fresh)


def check(result, name):
    return next(c for c in result.checks if c.name == name)


class CooldownTest(unittest.TestCase):
    def test_cases(self):
        self.assertEqual(cooldown_check(ts(72), NOW, 48, False).status, "pass")
        self.assertEqual(cooldown_check(ts(10), NOW, 48, False).status, "fail")
        self.assertEqual(cooldown_check(ts(10), NOW, 48, True).status, "pass")
        self.assertEqual(cooldown_check(None, NOW, 48, False).status, "unknown")
        self.assertEqual(cooldown_check("ieri", NOW, 48, False).status, "unknown")
        self.assertEqual(cooldown_check("2026-11-01T12:00:00Z", NOW, 48, False).status, "pass")


class AuditNpmTest(unittest.TestCase):
    def test_green(self):
        r = run(base())
        self.assertTrue(r.green, [(c.name, c.status, c.detail) for c in r.checks])
        self.assertEqual(r.candidate_version, "1.1.0")
        self.assertEqual(r.evidence["integrity"], "sha512-new")
        self.assertEqual([c.name for c in r.checks],
                         ["candidate", "same_major", "cooldown", "maintainers", "publisher", "install_scripts",
                          "new_dependencies", "provenance", "engines", "not_malicious", "not_deprecated"])

    def test_fresh_release(self):
        pk = base()
        pk["time"]["1.1.0"] = ts(10)
        self.assertEqual(check(run(pk), "cooldown").status, "fail")
        self.assertEqual(check(run(pk, accept_fresh=True), "cooldown").status, "pass")

    def test_prefers_older_version_past_cooldown(self):
        pk = base()
        pk["versions"]["1.2.0"] = version("1.2.0", "sha512-newest")
        pk["time"]["1.2.0"] = ts(5)
        r = run(pk)
        self.assertEqual(r.candidate_version, "1.1.0")
        self.assertTrue(r.green)

    def test_maintainer_added(self):
        pk = base()
        pk["versions"]["1.1.0"]["maintainers"].append({"name": "mallory"})
        self.assertEqual(check(run(pk), "maintainers").status, "fail")

    def test_publisher_not_maintainer(self):
        pk = base()
        pk["versions"]["1.1.0"]["_npmUser"] = {"name": "mallory"}
        self.assertEqual(check(run(pk), "publisher").status, "fail")

    def _trusted(self, pk, v, oidc="oidc:6d25", provider="github", attest=True):
        pk["versions"][v]["_npmUser"] = {"name": "GitHub Actions", "email": "npm-oidc-no-reply@github.com",
                                         "trustedPublisher": {"id": provider, "oidcConfigId": oidc}}
        if attest:
            pk["versions"][v]["dist"]["attestations"] = {"url": "https://registry.npmjs.org/-/npm/v1/attestations/x",
                                                         "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}

    def test_same_trusted_publisher_with_provenance_passes(self):
        pk = base()
        self._trusted(pk, "1.0.0")
        self._trusted(pk, "1.1.0")
        r = run(pk)
        self.assertEqual(check(r, "publisher").status, "pass")
        self.assertIn("trusted publisher", check(r, "publisher").detail)
        self.assertTrue(r.green, [(c.name, c.status, c.detail) for c in r.checks])

    def test_human_replaced_by_trusted_publisher_fails(self):
        pk = base()
        self._trusted(pk, "1.1.0")
        self.assertEqual(check(run(pk), "publisher").status, "fail")

    def test_different_oidc_config_fails(self):
        pk = base()
        self._trusted(pk, "1.0.0", oidc="oidc:aaaa")
        self._trusted(pk, "1.1.0", oidc="oidc:bbbb")
        self.assertEqual(check(run(pk), "publisher").status, "fail")

    def test_different_provider_fails(self):
        pk = base()
        self._trusted(pk, "1.0.0", provider="github")
        self._trusted(pk, "1.1.0", provider="gitlab")
        self.assertEqual(check(run(pk), "publisher").status, "fail")

    def test_trusted_publisher_without_provenance_fails(self):
        pk = base()
        self._trusted(pk, "1.0.0")
        self._trusted(pk, "1.1.0", attest=False)
        self.assertEqual(check(run(pk), "publisher").status, "fail")

    def test_malformed_trusted_publisher_fails(self):
        for bad in ("github", {"id": "github"}, {"oidcConfigId": "oidc:6d25"}, {"id": "", "oidcConfigId": ""}, None):
            pk = base()
            self._trusted(pk, "1.0.0")
            self._trusted(pk, "1.1.0")
            pk["versions"]["1.0.0"]["_npmUser"]["trustedPublisher"] = bad
            pk["versions"]["1.1.0"]["_npmUser"]["trustedPublisher"] = bad
            self.assertEqual(check(run(pk), "publisher").status, "fail", bad)

    def test_postinstall_added(self):
        pk = base()
        pk["versions"]["1.1.0"]["scripts"]["postinstall"] = "node steal.js"
        r = run(pk)
        self.assertEqual(check(r, "install_scripts").status, "fail")
        self.assertNotIn("steal", check(r, "install_scripts").detail)

    def test_new_dependency(self):
        pk = base()
        pk["versions"]["1.1.0"]["dependencies"]["evil"] = "1.0.0"
        self.assertEqual(check(run(pk), "new_dependencies").status, "fail")

    def test_provenance_dropped(self):
        pk = base()
        pk["versions"]["1.0.0"]["dist"]["attestations"] = {"url": "x"}
        self.assertEqual(check(run(pk), "provenance").status, "fail")

    def test_engines_unsatisfied(self):
        pk = base()
        pk["versions"]["1.1.0"]["engines"] = {"node": ">=24"}
        self.assertEqual(check(run(pk), "engines").status, "fail")

    def test_engines_unparseable_unknown(self):
        pk = base()
        pk["versions"]["1.1.0"]["engines"] = {"node": "workspace:*"}
        self.assertEqual(check(run(pk), "engines").status, "unknown")

    def test_owner_node_unknown(self):
        pk = base()
        pk["versions"]["1.1.0"]["engines"] = {"node": ">=18"}
        t = FakeTransport({packument_url("pkg"): Response(200, {}, json_bytes(pk))})
        f = Fetcher(t, ("registry.npmjs.org",), sleep=lambda x: None)
        r = audit_npm_global(ITEM, "1.1.0", f, NOW, 48, None, lambda n, v: False, "fid")
        self.assertEqual(check(r, "engines").status, "unknown")

    def test_only_major_jump(self):
        pk = base()
        pk["versions"] = {"1.0.0": version("1.0.0", "a"), "2.0.0": version("2.0.0", "b")}
        pk["time"] = {"1.0.0": ts(1000), "2.0.0": ts(100)}
        r = run(pk, fixed="1.1.0")
        self.assertEqual(check(r, "candidate").status, "fail")
        self.assertFalse(r.green)

    def test_malicious(self):
        self.assertEqual(check(run(base(), malicious=True), "not_malicious").status, "fail")

    def test_installed_version_unknown_to_registry(self):
        pk = base()
        del pk["versions"]["1.0.0"]
        r = run(pk)
        self.assertEqual(check(r, "maintainers").status, "unknown")
        self.assertFalse(r.green)

    def test_scoped_url(self):
        self.assertEqual(packument_url("@example/cli"), REGISTRY + "/@example%2fcli")

    def test_bad_name(self):
        with self.assertRaises(ValueError):
            packument_url("evil name;rm")
        with self.assertRaises(ValueError):
            packument_url("../etc")

    def test_registry_error(self):
        r = run(base(), status=500)
        self.assertFalse(r.green)
        self.assertEqual([(c.name, c.status) for c in r.checks], [("packument", "error")])

    def test_select_candidate_none(self):
        self.assertIsNone(select_candidate(base(), "1.0.0", "3.0.0", NOW, 48, False))


if __name__ == "__main__":
    unittest.main()
