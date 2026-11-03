import unittest

from vulnwatch import cli
from vulnwatch.i18n import set_language


class ConfirmTest(unittest.TestCase):
    def tearDown(self):
        set_language("en")

    def test_apply_prompt_english(self):
        self.assertIn("[y/N]", cli._confirm_prompt())
        for yes in ("y", "Y", "yes", " y "):
            self.assertTrue(cli._confirmed(yes), yes)
        for no in ("", "n", "s", "si", "no"):
            self.assertFalse(cli._confirmed(no), no)

    def test_apply_prompt_italian(self):
        set_language("it")
        self.assertIn("[s/N]", cli._confirm_prompt())
        for yes in ("s", "S", "si", "sì"):
            self.assertTrue(cli._confirmed(yes), yes)
        for no in ("", "n", "y", "no"):
            self.assertFalse(cli._confirmed(no), no)


class HelpTest(unittest.TestCase):
    def tearDown(self):
        set_language("en")

    def test_cli_help_english(self):
        h = cli._parser().format_help()
        self.assertIn("Daily vulnerability check", h)
        self.assertIn("status", h)
        self.assertIn("setup", h)

    def test_cli_help_italian(self):
        set_language("it")
        self.assertIn("Controllo giornaliero delle vulnerabilità", cli._parser().format_help())


if __name__ == "__main__":
    unittest.main()
