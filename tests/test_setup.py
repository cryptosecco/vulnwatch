import json
import os
import subprocess
import tempfile
import unittest

from vulnwatch import setup
from vulnwatch.config import load_config
from vulnwatch.i18n import set_language
from vulnwatch.proc import FakeRunner


def _exe(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("#!/bin/sh\n")
    os.chmod(path, 0o755)
    return path


class SetupTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = self._tmp.name
        self.home = os.path.join(root, "home")
        self.repo = os.path.join(root, "repo")
        self.cellar = os.path.join(root, "Cellar") + "/"
        os.makedirs(self.home)
        os.makedirs(os.path.join(self.repo, "config"))
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "aliases.json")) as f:
            aliases = f.read()
        with open(os.path.join(self.repo, "config", "aliases.json"), "w") as f:
            f.write(aliases)
        self.out = []
        self.kw = dict(brew_candidates=(), cellar_prefixes=(self.cellar,), system_patterns=())

    def tearDown(self):
        set_language("en")
        self._tmp.cleanup()

    def run_setup(self, argv, env=None, run=None, input_fn=None, euid=lambda: 501):
        def no_input(prompt):
            raise AssertionError("input() must not be called with --yes")
        return setup.main(argv, self.repo, run=run or FakeRunner({}), env=env if env is not None else {"PATH": "/usr/bin:/bin"},
                          home=self.home, user="alice", input_fn=input_fn or no_input, out=self.out.append, euid=euid,
                          detect_kwargs=self.kw)

    @property
    def cfg_path(self):
        return os.path.join(self.repo, "config", "config.json")


class SetupMainTest(SetupTestBase):
    def test_refuses_root(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview"], euid=lambda: 0), 1)
        self.assertFalse(os.path.exists(self.cfg_path))
        self.assertTrue(any("sudo" in line for line in self.out))

    def test_refuses_existing_config_without_force(self):
        with open(self.cfg_path, "w") as f:
            f.write("{}")
        self.assertEqual(self.run_setup(["--yes", "--no-preview"]), 1)
        with open(self.cfg_path) as f:
            self.assertEqual(f.read(), "{}")
        self.assertTrue(any("--force" in line for line in self.out))

    def test_force_overwrites(self):
        with open(self.cfg_path, "w") as f:
            f.write("{}")
        self.assertEqual(self.run_setup(["--yes", "--force", "--no-preview"]), 0)
        self.assertEqual(load_config(self.cfg_path).user, "alice")

    def test_detect_without_brew_and_npm(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview"]), 0)
        cfg = load_config(self.cfg_path)
        self.assertIsNone(cfg.brew)
        self.assertIsNone(cfg.npm_global)
        self.assertIsNone(cfg.path_node)
        self.assertFalse(cfg.auto_apply)
        self.assertEqual(cfg.hold, ())
        self.assertEqual(oct(os.stat(self.cfg_path).st_mode & 0o777), "0o644")

    def test_roots_with_spaces(self):
        os.makedirs(os.path.join(self.home, "My Projects"))
        self.assertEqual(self.run_setup(["--yes", "--no-preview", "--roots", "~/My Projects"]), 0)
        with open(self.cfg_path) as f:
            raw = json.load(f)
        self.assertEqual(raw["lockfile_roots"], ["~/My Projects"])
        self.assertTrue(load_config(self.cfg_path).lockfile_roots[0].endswith("/My Projects"))

    def test_language_default_en_when_lang_unset(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview"], env={"PATH": "/usr/bin"}), 0)
        self.assertEqual(load_config(self.cfg_path).language, "en")

    def test_language_it_from_lang(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview"], env={"PATH": "/usr/bin", "LANG": "it_IT.UTF-8"}), 0)
        self.assertEqual(load_config(self.cfg_path).language, "it")

    def test_language_it_from_apple_languages(self):
        run = FakeRunner({("/usr/bin/defaults", "read", "-g", "AppleLanguages"):
                          subprocess.CompletedProcess([], 0, '(\n    "it-IT",\n    "en-IT"\n)\n', "")})
        self.assertEqual(self.run_setup(["--yes", "--no-preview"], run=run), 0)
        self.assertEqual(load_config(self.cfg_path).language, "it")

    def test_lang_flag_wins(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview", "--lang", "it"]), 0)
        self.assertEqual(load_config(self.cfg_path).language, "it")

    def test_yes_is_non_interactive(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview"]), 0)

    def test_interactive_answers(self):
        os.makedirs(os.path.join(self.home, "Code"))
        answers = iter(["it", "~/Code, ~/My Projects"])
        self.assertEqual(self.run_setup(["--no-preview"], input_fn=lambda p: next(answers)), 0)
        with open(self.cfg_path) as f:
            raw = json.load(f)
        self.assertEqual(raw["language"], "it")
        self.assertEqual(raw["lockfile_roots"], ["~/Code", "~/My Projects"])

    def test_interactive_defaults_on_empty_answers(self):
        os.makedirs(os.path.join(self.home, "Code"))
        self.assertEqual(self.run_setup(["--no-preview"], input_fn=lambda p: ""), 0)
        with open(self.cfg_path) as f:
            raw = json.load(f)
        self.assertEqual(raw["lockfile_roots"], ["~/Code"])
        self.assertEqual(raw["language"], "en")

    def test_no_terminal_uses_detected_values(self):
        # A coding agent runs ./setup.sh with no terminal on stdin: input() raises EOFError at once.
        os.makedirs(os.path.join(self.home, "Code"))
        calls = []

        def no_terminal(prompt):
            calls.append(prompt)
            raise EOFError

        self.assertEqual(self.run_setup(["--no-preview"], input_fn=no_terminal), 0)
        self.assertEqual(len(calls), 1, "after the first EOF, setup must not ask again")
        with open(self.cfg_path) as f:
            raw = json.load(f)
        self.assertEqual(raw["language"], "en")
        self.assertEqual(raw["lockfile_roots"], ["~/Code"])
        self.assertTrue(any("--yes" in line for line in self.out))

    def test_written_config_protects_fixtures(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview"]), 0)
        cfg = load_config(self.cfg_path)
        self.assertIn(os.path.join(self.repo, "tests", "fixtures"), cfg.protected_dirs)
        with open(self.cfg_path) as f:
            raw = json.load(f)
        self.assertIn("~/Documents", raw["protected_dirs"])
        self.assertIn("~/Library/Mobile Documents", raw["protected_dirs"])

    def test_next_step_printed(self):
        self.assertEqual(self.run_setup(["--yes", "--no-preview"]), 0)
        self.assertTrue(any('sudo ./install.sh "$(git rev-parse HEAD)"' in line for line in self.out))


class DetectTest(SetupTestBase):
    def test_detect_brew(self):
        brew = _exe(os.path.join(self._tmp.name, "hb", "bin", "brew"))
        d = setup.detect(self.home, {"PATH": "/usr/bin"}, FakeRunner({}), "alice",
                         brew_candidates=("/nonexistent/brew", brew), cellar_prefixes=(self.cellar,), system_patterns=())
        self.assertEqual(d.brew, brew)

    def test_detect_npm_global(self):
        bindir = os.path.join(self._tmp.name, "nodebin")
        npm, node = _exe(os.path.join(bindir, "npm")), _exe(os.path.join(bindir, "node"))
        prefix = os.path.join(self.home, ".npm-global")
        run = FakeRunner({(npm, "config", "get", "prefix"): subprocess.CompletedProcess([], 0, prefix + "\n", "")})
        d = setup.detect(self.home, {"PATH": bindir + ":/usr/bin"}, run, "alice", **self.kw)
        self.assertEqual(d.npm_global, {"prefix": "~/.npm-global", "node": node, "npm": npm})
        self.assertEqual(d.path_node, node)

    def test_npm_prefix_failure_means_no_npm_global(self):
        bindir = os.path.join(self._tmp.name, "nodebin")
        _exe(os.path.join(bindir, "npm"))
        _exe(os.path.join(bindir, "node"))
        d = setup.detect(self.home, {"PATH": bindir}, FakeRunner({}), "alice", **self.kw)
        self.assertIsNone(d.npm_global)

    def test_detect_runtimes_dedup_and_globs(self):
        nvm_node = _exe(os.path.join(self.home, ".nvm", "versions", "node", "v22.1.0", "bin", "node"))
        bun = _exe(os.path.join(self.home, ".bun", "bin", "bun"))
        # Two PATH entries resolving to the same nvm node give no extra runtime (already covered by the nvm glob).
        link_dir = os.path.join(self._tmp.name, "links")
        os.makedirs(link_dir)
        os.symlink(nvm_node, os.path.join(link_dir, "node"))
        # A node inside a Homebrew Cellar is dropped: the brew inventory covers it.
        cellar_node = _exe(os.path.join(self.cellar, "node", "26.0.0", "bin", "node"))
        brew_bin = os.path.join(self._tmp.name, "hbbin")
        os.makedirs(brew_bin)
        os.symlink(cellar_node, os.path.join(brew_bin, "node"))
        # A standalone node on PATH is kept.
        other = _exe(os.path.join(self._tmp.name, "opt", "bin", "node"))
        env = {"PATH": ":".join([link_dir, os.path.dirname(nvm_node), brew_bin, os.path.dirname(other), "/usr/bin"])}
        d = setup.detect(self.home, env, FakeRunner({}), "alice", **self.kw)
        paths = [(r["label"], r["path"], r["product"]) for r in d.runtimes]
        self.assertIn(("nvm", "~/.nvm/versions/node/*/bin/node", "node"), paths)
        self.assertIn(("bun", "~/.bun/bin/bun", "bun"), paths)
        self.assertIn(("PATH", other, "node"), paths)
        self.assertEqual(len(paths), 3, paths)
        self.assertNotIn(cellar_node, [p for _, p, _ in paths])

    def test_detect_roots(self):
        os.makedirs(os.path.join(self.home, "Code"))
        os.makedirs(os.path.join(self.home, "Projects"))
        d = setup.detect(self.home, {"PATH": "/usr/bin"}, FakeRunner({}), "alice", **self.kw)
        self.assertEqual(d.roots, ["~/Code", "~/Projects"])


class CliDispatchTest(unittest.TestCase):
    def test_cli_dispatches_setup_without_config(self):
        from unittest import mock
        from vulnwatch import cli
        with mock.patch.object(setup, "main", return_value=7) as m:
            self.assertEqual(cli.main(["setup", "--yes"], config_path="/nonexistent/config.json"), 7)
        m.assert_called_once()
        self.assertEqual(m.call_args[0][0], ["--yes"])


class NoNetworkReviewFixTest(SetupTestBase):
    def test_npm_update_notifier_disabled(self):
        bindir = os.path.join(self._tmp.name, "nodebin")
        npm = _exe(os.path.join(bindir, "npm"))
        _exe(os.path.join(bindir, "node"))
        run = FakeRunner({(npm, "config", "get", "prefix"): subprocess.CompletedProcess([], 0, "/x\n", "")})
        setup.detect(self.home, {"PATH": bindir}, run, "alice", **self.kw)
        envs = [env for argv, env in run.calls if argv[0] == npm]
        self.assertEqual(len(envs), 1)
        self.assertEqual(envs[0].get("npm_config_update_notifier"), "false")


class RootsWarningReviewFixTest(SetupTestBase):
    def test_warns_about_roots_that_will_not_be_scanned(self):
        os.makedirs(os.path.join(self.home, "Code"))
        answers = iter(["en", "~/Code, ~/Documents/My Code, ~/Nope, relative/dir"])
        self.assertEqual(self.run_setup(["--no-preview"], input_fn=lambda p: next(answers)), 0)
        text = "\n".join(self.out)
        self.assertIn("~/Documents/My Code", text)
        self.assertIn("will not be scanned", text)
        self.assertIn("~/Nope", text)
        self.assertIn("does not exist", text)
        with open(self.cfg_path) as f:
            raw = json.load(f)
        self.assertNotIn("relative/dir", raw["lockfile_roots"])
        self.assertIn("~/Code", raw["lockfile_roots"])


if __name__ == "__main__":
    unittest.main()
