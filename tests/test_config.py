import json
import os
import tempfile
import unittest

from vulnwatch.config import ConfigError, load_config

REPO_CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.example.json")


class LoadConfigTest(unittest.TestCase):
    def test_repo_config_values(self):
        c = load_config(REPO_CONFIG)
        self.assertEqual(c.cooldown_hours, 48)
        self.assertIs(c.auto_apply, False)
        self.assertEqual(c.backfill_days, 90)
        self.assertEqual(c.hold, ())
        self.assertIn("cve.now", c.allowed_hosts)
        self.assertIn("f9gkulwameaj0boi.public.blob.vercel-storage.com", c.allowed_hosts)
        self.assertEqual(c.osv_ecosystems, ("npm", "PyPI"))
        self.assertEqual(c.chrome_team_id, "EQHXZ8M8AV")
        self.assertEqual(c.user, "your-username")
        home = os.path.expanduser("~")
        self.assertTrue(all(p.startswith(home + "/") for p in c.lockfile_roots))
        self.assertTrue(c.npm_global.prefix.startswith(home + "/"))
        self.assertTrue(c.aliases_file.endswith(os.path.join("config", "aliases.json")))
        self.assertTrue(os.path.isabs(c.aliases_file))

    def _write(self, data):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "config.json")
        with open(p, "w") as f:
            json.dump(data, f)
        return p

    def _base(self):
        with open(REPO_CONFIG) as f:
            return json.load(f)

    def test_rejects_unknown_key(self):
        data = self._base()
        data["surprise"] = 1
        with self.assertRaises(ConfigError):
            load_config(self._write(data))

    def test_rejects_missing_key(self):
        data = self._base()
        del data["cooldown_hours"]
        with self.assertRaises(ConfigError):
            load_config(self._write(data))

    def test_rejects_wrong_type(self):
        data = self._base()
        data["cooldown_hours"] = "48"
        with self.assertRaises(ConfigError):
            load_config(self._write(data))

    def test_rejects_bool_as_int(self):
        data = self._base()
        data["cooldown_hours"] = True
        with self.assertRaises(ConfigError):
            load_config(self._write(data))

    def test_host_intervals(self):
        self.assertEqual(load_config(REPO_CONFIG).host_intervals, {"cve.now": 2.0})
        data = self._base()
        data["host_intervals"] = {"evil.example": 1.0}
        with self.assertRaises(ConfigError):
            load_config(self._write(data))
        data["host_intervals"] = {"cve.now": "2"}
        with self.assertRaises(ConfigError):
            load_config(self._write(data))

    def test_rejects_bad_runtime_entry(self):
        data = self._base()
        data["runtimes"] = [{"label": "x", "path": "/x"}]
        with self.assertRaises(ConfigError):
            load_config(self._write(data))

    def test_language_defaults_to_en(self):
        data = self._base()
        data.pop("language", None)
        self.assertEqual(load_config(self._write(data)).language, "en")

    def test_language_it(self):
        data = self._base()
        data["language"] = "it"
        self.assertEqual(load_config(self._write(data)).language, "it")

    def test_language_invalid(self):
        data = self._base()
        data["language"] = "fr"
        with self.assertRaisesRegex(ConfigError, "language"):
            load_config(self._write(data))

    def test_nullable_brew_npm_path_node(self):
        data = self._base()
        data["brew"] = None
        data["npm_global"] = None
        data["path_node"] = None
        c = load_config(self._write(data))
        self.assertIsNone(c.brew)
        self.assertIsNone(c.npm_global)
        self.assertIsNone(c.path_node)

    def test_null_not_allowed_elsewhere(self):
        data = self._base()
        data["state_dir"] = None
        with self.assertRaises(ConfigError):
            load_config(self._write(data))

    def test_errors_are_english(self):
        data = self._base()
        del data["cooldown_hours"]
        with self.assertRaisesRegex(ConfigError, "missing keys: cooldown_hours"):
            load_config(self._write(data))
        data = self._base()
        data["surprise"] = 1
        with self.assertRaisesRegex(ConfigError, "unknown keys: surprise"):
            load_config(self._write(data))


if __name__ == "__main__":
    unittest.main()
