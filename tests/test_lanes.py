import dataclasses
import unittest

from vulnwatch.lanes import AUTO_CHANNELS, REASONS, classify
from vulnwatch.model import Finding, InventoryItem

NPM = InventoryItem("npm_global", "pnpm", "9.0.0", "npm", "npm_global", "/p")


def base(**kw):
    f = Finding("id1", "CVE-1", NPM, "exact", True, False, False, "osv", "9.1.0", "t", None)
    return dataclasses.replace(f, **kw)


class ClassifyTest(unittest.TestCase):
    def test_auto(self):
        f = classify(base(), hold=(), ignores={})
        self.assertEqual((f.lane, f.reasons), ("auto", ()))

    def test_critical_only_is_enough(self):
        self.assertEqual(classify(base(kev_confirmed=False, critical_confirmed=True), (), {}).lane, "auto")

    def test_hold(self):
        f = classify(base(), hold=("pnpm",), ignores={})
        self.assertEqual(f.lane, "manual")
        self.assertIn("on_hold", f.reasons)

    def test_cvenow_range(self):
        f = classify(base(range_source="cvenow"), (), {})
        self.assertEqual(f.lane, "manual")
        self.assertIn("range_not_primary", f.reasons)

    def test_not_kev_not_critical(self):
        f = classify(base(kev_confirmed=False), (), {})
        self.assertIn("not_kev_not_critical", f.reasons)

    def test_cask_is_manual(self):
        cask = InventoryItem("brew_cask", "blender", "5.2.3", None, "homebrew/cask", "/opt/homebrew")
        f = classify(base(item=cask), (), {})
        self.assertEqual(f.lane, "manual")
        self.assertIn("manual_channel", f.reasons)

    def test_other_tap_is_manual(self):
        f = classify(base(item=InventoryItem("brew_formula", "bun", "1.0", None, "oven-sh/bun", "/opt/homebrew")), (), {})
        self.assertIn("manual_channel", f.reasons)

    def test_runtime_formulae_always_manual(self):
        for name in ("python@3.14", "node", "node@22", "bun"):
            item = InventoryItem("brew_formula", name, "1.0", None, "homebrew/core", "/opt/homebrew")
            f = classify(base(item=item), (), {})
            self.assertEqual(f.lane, "manual", name)
            self.assertIn("manual_channel", f.reasons)
        ok = InventoryItem("brew_formula", "nodejs-helper", "1.0", None, "homebrew/core", "/opt/homebrew")
        self.assertEqual(classify(base(item=ok), (), {}).lane, "auto")

    def test_ignored(self):
        self.assertEqual(classify(base(), (), {"id1": "motivo"}).lane, "ignored")

    def test_malicious(self):
        f = classify(base(malicious=True), (), {})
        self.assertEqual((f.lane, f.reasons), ("malicious", ("malicious_package",)))

    def test_approximate(self):
        f = classify(base(match="approximate"), (), {})
        self.assertEqual((f.lane, f.reasons), ("manual", ("approximate_match",)))

    def test_no_patch(self):
        f = classify(base(fixed_version=None), (), {})
        self.assertEqual((f.lane, f.reasons), ("no_patch", ("fix_version_unknown",)))

    def test_reasons_known(self):
        cases = [base(range_source="cvenow", kev_confirmed=False), base(match="approximate"), base(malicious=True),
                 base(fixed_version=None), classify(base(), ("pnpm",), {})]
        for f in cases:
            for r in classify(f, ("pnpm",), {}).reasons:
                self.assertIn(r, REASONS)
        self.assertIn("audit_red", REASONS)

    def test_auto_channels(self):
        self.assertEqual(AUTO_CHANNELS, {("brew_formula", "homebrew/core"), ("npm_global", "npm_global")})


class ReasonTextTest(unittest.TestCase):
    def test_reason_text_both_languages(self):
        from vulnwatch.i18n import set_language
        from vulnwatch.lanes import reason_text
        self.assertEqual(reason_text("on_hold"), "on the hold list")
        set_language("it")
        try:
            self.assertEqual(reason_text("on_hold"), "nella lista di blocco")
        finally:
            set_language("en")
        self.assertEqual(reason_text("unknown_code"), "unknown_code")


if __name__ == "__main__":
    unittest.main()
