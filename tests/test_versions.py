import unittest

from vulnwatch.model import VersionRange as VR
from vulnwatch.versions import (
    VersionError,
    affected_by,
    compare,
    fixed_for,
    major,
    npm_satisfies,
    scheme_for,
)


class GenericTest(unittest.TestCase):
    def test_numeric_segments(self):
        self.assertEqual(compare("157.0.8089.0", "156.0.8078.80", "generic"), 1)

    def test_brew_revision_suffix(self):
        self.assertEqual(compare("15.0.0_1", "15.0.0", "generic"), 1)

    def test_v_prefix(self):
        self.assertEqual(compare("v22.23.4", "22.23.4", "generic"), 0)

    def test_alpha_suffix_is_prerelease(self):
        self.assertEqual(compare("1.0beta", "1.0", "generic"), -1)

    def test_empty_raises(self):
        with self.assertRaises(VersionError):
            compare("", "1.0", "generic")


class SemverTest(unittest.TestCase):
    def test_prerelease_and_numeric(self):
        self.assertEqual(compare("1.2.3-rc.1", "1.2.3", "semver"), -1)
        self.assertEqual(compare("1.2.10", "1.2.9", "semver"), 1)

    def test_prerelease_identifiers(self):
        self.assertEqual(compare("1.0.0-alpha", "1.0.0-alpha.1", "semver"), -1)
        self.assertEqual(compare("1.0.0-alpha.1", "1.0.0-beta", "semver"), -1)
        self.assertEqual(compare("1.0.0-beta.2", "1.0.0-beta.11", "semver"), -1)

    def test_build_ignored(self):
        self.assertEqual(compare("1.2.3+abc", "1.2.3", "semver"), 0)

    def test_unparseable_raises(self):
        for bad in ("", "abc"):
            with self.assertRaises(VersionError):
                compare(bad, "1.0.0", "semver")


class Pep440Test(unittest.TestCase):
    def test_ordering(self):
        self.assertEqual(compare("2.0rc1", "2.0", "pep440"), -1)
        self.assertEqual(compare("2.0.post1", "2.0", "pep440"), 1)
        self.assertEqual(compare("1!1.0", "2.0", "pep440"), 1)
        self.assertEqual(compare("2.0.dev1", "2.0a1", "pep440"), -1)
        self.assertEqual(compare("2.0", "2.0.0", "pep440"), 0)

    def test_unparseable_raises(self):
        with self.assertRaises(VersionError):
            compare("not a version", "1.0", "pep440")


class RangeTest(unittest.TestCase):
    def test_fixed_bound(self):
        self.assertIs(affected_by("1.4.0", [VR("0", "1.5.0", None)], [], "semver"), True)
        self.assertIs(affected_by("1.5.0", [VR("0", "1.5.0", None)], [], "semver"), False)

    def test_introduced_bound(self):
        self.assertIs(affected_by("1.9.0", [VR("2.0.0", "2.5.0", None)], [], "semver"), False)

    def test_last_affected(self):
        self.assertIs(affected_by("0.9.2.6", [VR(None, None, "0.9.2.6")], [], "generic"), True)
        self.assertIs(affected_by("0.9.2.8", [VR(None, None, "0.9.2.6")], [], "generic"), False)

    def test_explicit_versions(self):
        self.assertIs(affected_by("1.0.1", [], ["1.0.1"], "semver"), True)

    def test_undecidable(self):
        self.assertIsNone(affected_by("1.0", [], [], "generic"))
        self.assertIsNone(affected_by("garbage!!", [VR("0", "2.0.0", None)], [], "semver"))

    def test_year_like_bound_is_skipped(self):
        rs = [VR(None, "11.0", None), VR(None, "2020", None), VR(None, "10.15", None)]
        self.assertIs(affected_by("27.0.1", rs, [], "generic"), False)
        self.assertIs(affected_by("10.14.6", rs, [], "generic"), True)
        self.assertIsNone(affected_by("27.0.1", [VR(None, "2021-005", None)], [], "generic"))
        self.assertEqual(fixed_for("10.14.6", [VR(None, "2020", None), VR(None, "10.15", None)], "generic"), "10.15")

    def test_year_versions_compare_with_each_other(self):
        self.assertIs(affected_by("20260817.0", [VR(None, "20261001.0", None)], [], "generic"), True)

    def test_fixed_for(self):
        rs = [VR("0", "1.5.0", None), VR("2.0.0", "2.1.0", None)]
        self.assertEqual(fixed_for("1.4.0", rs, "semver"), "1.5.0")
        self.assertEqual(fixed_for("2.0.5", rs, "semver"), "2.1.0")
        self.assertIsNone(fixed_for("3.0.0", rs, "semver"))


class NpmRangeTest(unittest.TestCase):
    def test_ranges(self):
        self.assertTrue(npm_satisfies("22.23.4", ">=20"))
        self.assertFalse(npm_satisfies("22.23.4", ">=24.22.1 <25 || >=26.12.1"))
        self.assertTrue(npm_satisfies("24.22.1", ">=24.22.1 <25 || >=26.12.1"))
        self.assertTrue(npm_satisfies("18.0.5", "~18.0.0"))
        self.assertFalse(npm_satisfies("18.1.0", "~18.0.0"))
        self.assertTrue(npm_satisfies("1.2.3", "1.x"))
        self.assertFalse(npm_satisfies("1.2.3", "1.0.0 - 1.2.0"))
        self.assertTrue(npm_satisfies("1.9.0", "^1.2.3"))
        self.assertFalse(npm_satisfies("2.0.0", "^1.2.3"))
        self.assertTrue(npm_satisfies("0.2.5", "^0.2.3"))
        self.assertFalse(npm_satisfies("0.3.0", "^0.2.3"))
        self.assertTrue(npm_satisfies("5.0.0", "*"))
        self.assertTrue(npm_satisfies("1.2.9", "1.2.*"))

    def test_unsupported_raises(self):
        with self.assertRaises(VersionError):
            npm_satisfies("1.0.0", "workspace:*")


class HelpersTest(unittest.TestCase):
    def test_major(self):
        self.assertEqual(major("15.0.0_1", "generic"), 15)
        self.assertEqual(major("v22.23.4", "semver"), 22)
        self.assertEqual(major("2.0rc1", "pep440"), 2)

    def test_scheme_for(self):
        self.assertEqual(scheme_for("npm_global", "npm"), "semver")
        self.assertEqual(scheme_for("lockfile_pkg", "PyPI"), "pep440")
        self.assertEqual(scheme_for("brew_formula", None), "generic")


if __name__ == "__main__":
    unittest.main()
