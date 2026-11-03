import json
import os
import plistlib
import subprocess
import tempfile
import unittest

from tests.helpers import load_fixture
from tests.test_config import REPO_CONFIG
from vulnwatch.config import RuntimeSpec, load_config
from vulnwatch.inventory import brew, npm, system
from vulnwatch.proc import FakeRunner


def cp(argv, out="", err="", code=0):
    return subprocess.CompletedProcess(argv, code, out, err)


def make_app(root, name, bundle_id, version, bundle_name):
    path = os.path.join(root, name)
    os.makedirs(os.path.join(path, "Contents"))
    with open(os.path.join(path, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump({"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version,
                       "CFBundleName": bundle_name}, f)
    return path


class SystemTest(unittest.TestCase):
    def test_macos_item(self):
        argv = ["/usr/bin/sw_vers", "-productVersion"]
        item = system.macos_item(FakeRunner({tuple(argv): cp(argv, "27.0.1\n")}))
        self.assertEqual((item.kind, item.name, item.version), ("macos", "macos", "27.0.1"))

    def test_apps_reads_plist_and_team(self):
        d = tempfile.mkdtemp()
        p = make_app(d, "Google Chrome.app", "com.google.Chrome", "157.0.8089.0", "Google Chrome")
        argv = ["/usr/bin/codesign", "-dv", "--verbose=2", p]
        run = FakeRunner({tuple(argv): cp(argv, "", "Executable=x\nTeamIdentifier=EQHXZ8M8AV\n")})
        items = system.apps([d], run)
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertEqual((it.kind, it.name, it.version), ("app", "com.google.Chrome", "157.0.8089.0"))
        self.assertEqual(it.channel, "google_updater")
        self.assertEqual(it.team_id, "EQHXZ8M8AV")
        self.assertEqual(it.display_name, "Google Chrome")

    def test_other_app_has_no_channel(self):
        d = tempfile.mkdtemp()
        make_app(d, "Foo.app", "com.example.foo", "1.0", "Foo")
        it = system.apps([d], FakeRunner({}))[0]
        self.assertIsNone(it.channel)
        self.assertIsNone(it.team_id)

    def test_bad_plist_skipped(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "Bad.app", "Contents"))
        with open(os.path.join(d, "Bad.app", "Contents", "Info.plist"), "w") as f:
            f.write("not a plist")
        self.assertEqual(system.apps([d], FakeRunner({})), [])

    def test_missing_dir_ignored(self):
        self.assertEqual(system.apps(["/nonexistent/dir"], FakeRunner({})), [])

    def test_runtimes_glob_and_version(self):
        d = tempfile.mkdtemp()
        paths = []
        for v in ("20.20.2", "24.22.1"):
            os.makedirs(os.path.join(d, v))
            p = os.path.join(d, v, "node")
            with open(p, "w") as f:
                f.write("#")
            os.chmod(p, 0o755)
            paths.append(p)
        run = FakeRunner({(paths[0], "--version"): cp([], "v20.20.2\n"), (paths[1], "--version"): cp([], "v24.22.1\n")})
        items = system.runtimes([RuntimeSpec("App bundle", os.path.join(d, "*", "node"), "node")], run)
        self.assertEqual(sorted(i.version for i in items), ["20.20.2", "24.22.1"])
        self.assertTrue(all(i.kind == "runtime" and i.name == "node" for i in items))
        self.assertEqual(run.calls[0][1], {"PATH": "/usr/bin:/bin"})

    def test_runtime_missing_or_failing_skipped(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "node")
        with open(p, "w") as f:
            f.write("#")
        os.chmod(p, 0o755)
        run = FakeRunner({(p, "--version"): cp([], "", "boom", 1)})
        self.assertEqual(system.runtimes([RuntimeSpec("x", p, "node"), RuntimeSpec("y", "/nope/node", "node")], run), [])


class BrewTest(unittest.TestCase):
    def test_formula_fixture(self):
        items = brew.brew_items(load_fixture("brew/info_formula.json"))
        self.assertEqual(len(items), 1)
        self.assertEqual((items[0].kind, items[0].name, items[0].channel), ("brew_formula", "aom", "homebrew/core"))
        self.assertTrue(items[0].version)

    def test_two_kegs_use_linked_or_newest(self):
        f = {"name": "aom", "tap": "homebrew/core", "installed": [{"version": "3.15.2"}, {"version": "3.15.3"}]}
        self.assertEqual(brew.brew_items({"formulae": [dict(f, linked_keg="3.15.3")]})[0].version, "3.15.3")
        self.assertEqual(brew.brew_items({"formulae": [dict(f, linked_keg="3.15.2")]})[0].version, "3.15.2")
        self.assertEqual(brew.brew_items({"formulae": [f]})[0].version, "3.15.3")

    def test_cask_fixture(self):
        it = brew.brew_items(load_fixture("brew/info_cask.json"))[0]
        self.assertEqual((it.kind, it.name, it.channel), ("brew_cask", "blender", "homebrew/cask"))

    def test_env(self):
        self.assertEqual(brew.BREW_ENV["HOMEBREW_NO_AUTOREMOVE"], "1")
        self.assertEqual(brew.BREW_ENV["HOMEBREW_NO_INSTALL_CLEANUP"], "1")
        self.assertEqual(brew.BREW_ENV["HOMEBREW_NO_AUTO_UPDATE"], "1")
        self.assertEqual(brew.BREW_ENV["HOMEBREW_NO_ANALYTICS"], "1")


class NpmTest(unittest.TestCase):
    def _pkg(self, root, rel, name, version="1.0.0"):
        d = os.path.join(root, "lib", "node_modules", rel)
        os.makedirs(d)
        with open(os.path.join(d, "package.json"), "w") as f:
            json.dump({"name": name, "version": version}, f)

    def test_scoped_and_plain(self):
        prefix = tempfile.mkdtemp()
        self._pkg(prefix, "@example/cli", "@example/cli", "0.5.0")
        self._pkg(prefix, "pnpm", "pnpm", "9.0.0")
        items = npm.npm_globals(prefix)
        self.assertEqual(sorted(i.name for i in items), ["@example/cli", "pnpm"])
        self.assertTrue(all(i.ecosystem == "npm" and i.channel == "npm_global" and i.location == prefix for i in items))

    def test_name_mismatch_skipped(self):
        prefix = tempfile.mkdtemp()
        self._pkg(prefix, "pnpm", "evil")
        self.assertEqual(npm.npm_globals(prefix), [])

    def test_symlinked_package_skipped(self):
        prefix = tempfile.mkdtemp()
        target = tempfile.mkdtemp()
        with open(os.path.join(target, "package.json"), "w") as f:
            json.dump({"name": "linked", "version": "1.0.0"}, f)
        os.makedirs(os.path.join(prefix, "lib", "node_modules"))
        os.symlink(target, os.path.join(prefix, "lib", "node_modules", "linked"))
        self.assertEqual(npm.npm_globals(prefix), [])


class ConfigRuntimesTest(unittest.TestCase):
    def test_repo_runtimes(self):
        c = load_config(REPO_CONFIG)
        self.assertTrue(len(c.runtimes) >= 1)
        self.assertTrue(all(r.product in ("node", "bun") for r in c.runtimes))


if __name__ == "__main__":
    unittest.main()
