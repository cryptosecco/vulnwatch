import unittest

from tests.helpers import NOW
from vulnwatch.match import Alias, build_findings, canonical_id, normalize
from vulnwatch.model import Advisory, Affected, InventoryItem
from vulnwatch.model import VersionRange as VR


def adv(id_, source, affected, aliases=(), cvss=None, severity=None, kev=False, malicious=False, title="t"):
    return Advisory(id_, tuple(aliases), source, title, "", cvss, severity, kev, tuple(affected), "2026-11-01", None, malicious)


def eco(ecosystem, package, ranges=(), versions=()):
    return Affected(ecosystem, package, None, None, tuple(ranges), tuple(versions))


def vp(vendor, product, ranges=(), versions=()):
    return Affected(None, None, vendor, product, tuple(ranges), tuple(versions))


PNPM_OLD = InventoryItem("npm_global", "pnpm", "9.0.0", "npm", "npm_global", "/p")
PNPM_NEW = InventoryItem("npm_global", "pnpm", "9.2.0", "npm", "npm_global", "/p")
CHROME = InventoryItem("app", "com.google.Chrome", "157.0.8089.0", None, "google_updater", "/Applications/Google Chrome.app",
                       "EQHXZ8M8AV", "Google Chrome")
ALIASES = [Alias("google", "chromium", "app", "com.google.Chrome"), Alias("google", "chrome", "app", "com.google.Chrome")]


class NormalizeTest(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize("Node.js"), "node js")
        self.assertEqual(normalize("  Oven-SH "), "oven sh")

    def test_canonical_prefers_cve(self):
        self.assertEqual(canonical_id(adv("GHSA-aaaa-bbbb-cccc", "osv", [], aliases=["CVE-2026-1"])), "CVE-2026-1")

    def test_canonical_ghsa_case(self):
        self.assertEqual(canonical_id(adv("GHSA-4XM8-RG9H-JHQ2", "cvenow", [])), "GHSA-4xm8-rg9h-jhq2")
        self.assertEqual(canonical_id(adv("MAL-2026-1", "osv", [], aliases=["GHSA-ABCD-efgh-1234"])), "GHSA-abcd-efgh-1234")


class BuildFindingsTest(unittest.TestCase):
    def test_ecosystem_exact(self):
        a = adv("GHSA-aaaa-bbbb-cccc", "osv", [eco("npm", "pnpm", [VR("0", "9.1.0", None)])], aliases=["CVE-2026-9"])
        fs = build_findings([a], [PNPM_OLD], [], NOW)
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual((f.match, f.range_source, f.fixed_version, f.canonical_id), ("exact", "osv", "9.1.0", "CVE-2026-9"))

    def test_not_affected(self):
        a = adv("GHSA-aaaa-bbbb-cccc", "osv", [eco("npm", "pnpm", [VR("0", "9.1.0", None)])])
        self.assertEqual(build_findings([a], [PNPM_NEW], [], NOW), [])

    def test_kev_plus_cverecord_alias_prefix(self):
        k = adv("CVE-2026-50", "kev", [vp("Google", "Chromium V8")], kev=True)
        r = adv("CVE-2026-50", "cverecord", [vp("Google", "Chrome", [VR(None, "158.0", None)])], cvss=8.8)
        fs = build_findings([k, r], [CHROME], ALIASES, NOW)
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual((f.kev_confirmed, f.range_source, f.fixed_version, f.match), (True, "cverecord", "158.0", "exact"))

    def test_primary_says_not_affected_drops_kev_only_match(self):
        k = adv("CVE-2026-50", "kev", [vp("Google", "Chromium V8")], kev=True)
        r = adv("CVE-2026-50", "cverecord", [vp("Google", "Chrome", [VR(None, "150.0", None)])])
        self.assertEqual(build_findings([k, r], [CHROME], ALIASES, NOW), [])

    def test_cvenow_cannot_hide_a_kev_match(self):
        k = adv("CVE-2026-50", "kev", [vp("Google", "Chromium V8")], kev=True)
        n = adv("CVE-2026-50", "cvenow", [vp("Google", "Chrome", [VR(None, "150.0", None)])])
        fs = build_findings([k, n], [CHROME], ALIASES, NOW)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].match, "approximate")

    def test_loose_match_is_approximate(self):
        app = InventoryItem("app", "com.example.widget", "1.0", None, None, "/Applications/Widget.app", None, "Widget")
        a = adv("CVE-2026-60", "cverecord", [vp("Example Corp", "Widget", [VR(None, "2.0", None)])])
        f = build_findings([a], [app], [], NOW)[0]
        self.assertEqual((f.match, f.range_source), ("approximate", "cverecord"))

    def test_loose_never_on_npm_or_short_names(self):
        a = adv("CVE-2026-61", "cverecord", [vp("someone", "pnpm", [VR(None, "99.0", None)])])
        self.assertEqual(build_findings([a], [PNPM_OLD], [], NOW), [])
        gh = InventoryItem("brew_formula", "gh", "2.0", None, "homebrew/core", "/opt/homebrew")
        b = adv("CVE-2026-62", "cverecord", [vp("x", "gh", [VR(None, "9.0", None)])])
        self.assertEqual(build_findings([b], [gh], [], NOW), [])

    def test_undecidable_is_approximate(self):
        a = adv("CVE-2026-70", "kev", [vp("Google", "Chrome")], kev=True)
        f = build_findings([a], [CHROME], ALIASES, NOW)[0]
        self.assertEqual((f.match, f.range_source, f.fixed_version), ("approximate", None, None))

    def test_cvenow_kev_claim_not_trusted(self):
        n = adv("GHSA-aaaa-bbbb-cccc", "cvenow", [eco("npm", "pnpm", [VR("0", "9.1.0", None)])], kev=True)
        f = build_findings([n], [PNPM_OLD], [], NOW)[0]
        self.assertIs(f.kev_confirmed, False)
        self.assertEqual(f.range_source, "cvenow")

    def test_critical_from_primary_only(self):
        n = adv("CVE-2026-80", "cvenow", [eco("npm", "pnpm", [VR("0", "9.1.0", None)])], cvss=10.0)
        o = adv("GHSA-aaaa-bbbb-cccc", "osv", [eco("npm", "pnpm", [VR("0", "9.1.0", None)])], aliases=["CVE-2026-80"], severity="critical")
        self.assertIs(build_findings([n], [PNPM_OLD], [], NOW)[0].critical_confirmed, False)
        self.assertIs(build_findings([n, o], [PNPM_OLD], [], NOW)[0].critical_confirmed, True)

    def test_pypi_name_normalized(self):
        item = InventoryItem("lockfile_pkg", "flask-login", "0.6.2", "PyPI", None, "/x/requirements.txt")
        a = adv("PYSEC-1", "osv", [eco("PyPI", "Flask_Login", [VR("0", "0.6.3", None)])])
        self.assertEqual(len(build_findings([a], [item], [], NOW)), 1)

    def test_malicious_flag(self):
        a = adv("MAL-2026-1", "osv", [eco("npm", "pnpm", versions=["9.0.0"])], malicious=True)
        self.assertIs(build_findings([a], [PNPM_OLD], [], NOW)[0].malicious, True)

    def test_streams_a_generator(self):
        a = adv("GHSA-aaaa-bbbb-cccc", "osv", [eco("npm", "pnpm", [VR("0", "9.1.0", None)])])
        self.assertEqual(len(build_findings((x for x in [a]), [PNPM_OLD], [], NOW)), 1)


if __name__ == "__main__":
    unittest.main()
