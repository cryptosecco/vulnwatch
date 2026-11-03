import unittest

from vulnwatch.model import (
    Advisory,
    Affected,
    AuditResult,
    Check,
    Finding,
    InventoryItem,
    VersionRange,
    advisory_from_dict,
    audit_from_dict,
    finding_from_dict,
    finding_id,
    to_dict,
)


def make_advisory():
    return Advisory(
        id="GHSA-xxxx-yyyy-zzzz",
        aliases=("CVE-2026-1",),
        source="osv",
        title="t",
        description="d",
        cvss=None,
        severity="critical",
        kev=False,
        affected=(
            Affected(
                ecosystem="npm",
                package="pnpm",
                vendor=None,
                product=None,
                ranges=(VersionRange("0", "9.1.0", None), VersionRange(None, None, "2.0")),
                versions=("1.0.0", "1.0.1"),
            ),
        ),
        published="2026-11-01T00:00:00Z",
        modified=None,
        malicious=False,
    )


def make_finding():
    item = InventoryItem("npm_global", "pnpm", "9.0.0", "npm", "npm_global", "/p", None, None)
    return Finding(
        id=finding_id("CVE-2026-1", "npm_global", "pnpm", "/p"),
        canonical_id="CVE-2026-1",
        item=item,
        match="exact",
        kev_confirmed=True,
        critical_confirmed=False,
        malicious=False,
        range_source="osv",
        fixed_version="9.1.0",
        title="t",
        published=None,
        lane="auto",
        reasons=("a", "b"),
    )


class FindingIdTest(unittest.TestCase):
    def test_stable_and_short(self):
        a = finding_id("CVE-1", "npm_global", "a", "/p")
        self.assertEqual(a, finding_id("CVE-1", "npm_global", "a", "/p"))
        self.assertEqual(len(a), 12)

    def test_location_matters(self):
        self.assertNotEqual(
            finding_id("CVE-1", "npm_global", "a", "/p"),
            finding_id("CVE-1", "npm_global", "a", "/q"),
        )


class RoundTripTest(unittest.TestCase):
    def test_advisory_roundtrip(self):
        adv = make_advisory()
        self.assertEqual(advisory_from_dict(to_dict(adv)), adv)

    def test_finding_roundtrip(self):
        f = make_finding()
        self.assertEqual(finding_from_dict(to_dict(f)), f)

    def test_audit_roundtrip(self):
        a = AuditResult("abc", "1.1.0", [Check("cooldown", "pass", "ok")], {"integrity": "x"})
        b = audit_from_dict(to_dict(a))
        self.assertEqual(b.green, a.green)
        self.assertEqual(b.checks[0].name, "cooldown")
        self.assertEqual(b.evidence, {"integrity": "x"})


class AuditGreenTest(unittest.TestCase):
    def test_empty_checks_not_green(self):
        self.assertFalse(AuditResult("x", None, [], {}).green)

    def test_any_non_pass_not_green(self):
        a = AuditResult("x", "1", [Check("a", "pass", ""), Check("b", "unknown", "")], {})
        self.assertFalse(a.green)

    def test_all_pass_green(self):
        self.assertTrue(AuditResult("x", "1", [Check("a", "pass", "")], {}).green)


if __name__ == "__main__":
    unittest.main()
