import unittest

from vulnwatch.sanitize import clean_text


class CleanTextTest(unittest.TestCase):
    def test_strips_ansi(self):
        self.assertEqual(clean_text("a\x1b[31mb\x1b[0m"), "ab")

    def test_strips_osc_sequence(self):
        self.assertEqual(clean_text("a\x1b]0;title\x07b"), "ab")

    def test_strips_bidi_and_zero_width(self):
        self.assertEqual(clean_text("x‮y​z⁦"), "xyz")

    def test_controls_removed_tabs_newlines_become_space(self):
        self.assertEqual(clean_text("a\tb\nc\x00d"), "a b cd")

    def test_collapses_whitespace(self):
        self.assertEqual(clean_text("  a   b  "), "a b")

    def test_non_strings(self):
        self.assertEqual(clean_text(None), "")
        self.assertEqual(clean_text(9.8), "9.8")

    def test_truncates_with_ellipsis(self):
        s = clean_text("x" * 600)
        self.assertEqual(len(s), 500)
        self.assertTrue(s.endswith("…"))

    def test_custom_max_len(self):
        self.assertEqual(clean_text("abcdef", max_len=4), "abc…")


if __name__ == "__main__":
    unittest.main()
