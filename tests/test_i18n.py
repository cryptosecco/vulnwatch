import os
import unittest
from unittest import mock

from vulnwatch import i18n
from vulnwatch.i18n import language, set_language, t


class I18nTest(unittest.TestCase):
    def tearDown(self):
        set_language("en")

    def test_default_en(self):
        self.assertEqual(language(), "en")
        self.assertEqual(t("Report", "Rapporto"), "Report")

    def test_switch_it(self):
        set_language("it")
        self.assertEqual(language(), "it")
        self.assertEqual(t("Report", "Rapporto"), "Rapporto")

    def test_unknown_language_raises(self):
        with self.assertRaises(ValueError):
            set_language("fr")
        self.assertEqual(language(), "en")

    def test_languages(self):
        self.assertEqual(i18n.LANGUAGES, ("en", "it"))


class CliSetsLanguageTest(unittest.TestCase):
    def tearDown(self):
        set_language("en")

    def test_cli_applies_config_language(self):
        import json
        import tempfile
        from vulnwatch import cli
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo, "config", "config.example.json")) as f:
            data = json.load(f)
        data["language"] = "it"
        data["user"] = "someone-else"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "config.json")
            with open(p, "w") as f:
                json.dump(data, f)
            with mock.patch("builtins.print"):
                cli.main(["report"], config_path=p)
        self.assertEqual(language(), "it")


if __name__ == "__main__":
    unittest.main()
