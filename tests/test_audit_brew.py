import copy
import json
import os
import subprocess
import tempfile
import unittest
from datetime import timedelta

from tests.helpers import NOW, fixture_path, json_bytes, load_fixture
from vulnwatch.audit.brew import audit_cask, audit_formula, last_change
from vulnwatch.brew_client import BrewClient, parse_dry_run
from vulnwatch.model import InventoryItem
from vulnwatch.net import FakeTransport, Fetcher, Response
from vulnwatch.proc import FakeRunner

BREW = "/opt/homebrew/bin/brew"
FORMULA = InventoryItem("brew_formula", "aom", "3.15.2", None, "homebrew/core", "/opt/homebrew")
CASK = InventoryItem("brew_cask", "blender", "5.2.2", None, "homebrew/cask", "/opt/homebrew")
DRY_OK = "==> Would upgrade 1 outdated package\naom 3.15.2 -> 3.15.3 (4.4MB)\n"
DRY_CASK = "==> Would upgrade 1 outdated package\nblender 5.2.2 -> 5.2.3\n"


def cp(out="", code=0, err=""):
    return subprocess.CompletedProcess([], code, out, err)


def gh_url(repo, path):
    return "https://api.github.com/repos/%s/commits?path=%s&per_page=1" % (repo, path)


def commits(hours_ago):
    d = (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return Response(200, {}, json_bytes([{"sha": "x", "commit": {"committer": {"date": d}}}]))


class Env:
    def __init__(self, info_formula=None, info_cask=None, dry=DRY_OK, dry_cask=DRY_CASK, services="[]",
                 commit_hours=120, commit_resp=None):
        self.cellar = tempfile.mkdtemp()
        fi = info_formula or load_fixture("brew/info_formula.json")
        ci = info_cask or self.cask_info()
        self.run = FakeRunner({
            (BREW, "info", "--json=v2", "--formula", "aom"): cp(json.dumps(fi)),
            (BREW, "info", "--json=v2", "--cask", "blender"): cp(json.dumps(ci)),
            (BREW, "upgrade", "--dry-run", "--formula", "aom"): cp(dry),
            (BREW, "upgrade", "--dry-run", "--cask", "blender"): cp(dry_cask),
            (BREW, "services", "info", "--all", "--json"): cp(services),
            (BREW, "ruby", "-e", "puts Utils::Bottles.tag.to_s"): cp("arm64_golden_gate\n"),
            (BREW, "--cellar"): cp(self.cellar + "\n"),
        })
        resp = commit_resp or commits(commit_hours)
        self.fetcher = Fetcher(FakeTransport({
            gh_url("Homebrew/homebrew-core", "Formula/a/aom.rb"): resp,
            gh_url("Homebrew/homebrew-cask", "Casks/b/blender.rb"): resp,
        }), ("api.github.com",), sleep=lambda x: None)
        self.brew = BrewClient(self.run, BREW)

    @staticmethod
    def cask_info():
        ci = copy.deepcopy(load_fixture("brew/info_cask.json"))
        ci["casks"][0]["installed"] = "5.2.2"
        return ci

    def keg(self, text):
        d = os.path.join(self.cellar, "aom", "3.15.2", ".brew")
        os.makedirs(d)
        with open(os.path.join(d, "aom.rb"), "w") as f:
            f.write(text)

    def formula(self, fixed="3.15.3", **kw):
        return audit_formula(FORMULA, fixed, self.brew, self.fetcher, NOW, 48, "fid", **kw)

    def cask(self, fixed="5.2.3"):
        return audit_cask(CASK, fixed, self.brew, self.fetcher, NOW, 48, "fid")


def status(result, name):
    return next(c.status for c in result.checks if c.name == name)


def formula_info(**changes):
    fi = copy.deepcopy(load_fixture("brew/info_formula.json"))
    fi["formulae"][0].update(changes)
    return fi


class DryRunTest(unittest.TestCase):
    def test_real_fixture_has_dependent(self):
        with open(fixture_path("brew/dryrun_aom.txt")) as f:
            dr = parse_dry_run(f.read())
        self.assertIn(("aom", "3.15.2", "3.15.3"), dr.upgrades)
        self.assertIn("ffmpeg-full", [u[0] for u in dr.upgrades])
        self.assertEqual(dr.installs, [])

    def test_dependency_install(self):
        dr = parse_dry_run("==> Would install 1 dependency:\nicu4c@79 79.1\n==> Would upgrade 1 outdated package\naom 1 -> 2 (1MB)\n")
        self.assertEqual(dr.installs, ["icu4c@79"])
        self.assertEqual(dr.upgrades, [("aom", "1", "2")])

    def test_line_without_arrow_counts_as_touched(self):
        dr = parse_dry_run("==> Would upgrade 2 outdated packages\naom 1 -> 2 (1MB)\nharfbuzz 11.0.0\n")
        self.assertEqual([u[0] for u in dr.upgrades], ["aom", "harfbuzz"])

    def test_unparsable_line_in_section_raises(self):
        with self.assertRaises(ValueError):
            parse_dry_run("==> Would install 3 dependencies:\nfoo bar baz qux\n")

    def test_unknown_section(self):
        with self.assertRaises(ValueError):
            parse_dry_run("==> Would frobnicate 2 things\n")


class FormulaTest(unittest.TestCase):
    def test_green(self):
        r = Env().formula()
        self.assertTrue(r.green, [(c.name, c.status, c.detail) for c in r.checks])
        self.assertEqual(r.candidate_version, "3.15.3")
        self.assertEqual([c.name for c in r.checks],
                         ["tap_core", "candidate", "same_major", "bottle_available", "dry_run_only_target",
                          "post_install_unchanged", "caveats_unchanged", "not_running_service", "not_deprecated", "cooldown"])

    def test_brew_env_used(self):
        e = Env()
        e.formula()
        env = e.run.calls[0][1]
        self.assertEqual(env["HOMEBREW_NO_AUTOREMOVE"], "1")
        self.assertEqual(env["HOMEBREW_NO_AUTO_UPDATE"], "1")
        self.assertIn("/opt/homebrew/bin", env["PATH"])

    def test_not_core(self):
        self.assertEqual(status(Env(info_formula=formula_info(tap="someone/tap")).formula(), "tap_core"), "fail")

    def test_no_bottle_for_tag(self):
        fi = formula_info()
        fi["formulae"][0]["bottle"]["stable"]["files"] = {"x86_64_linux": {}}
        self.assertEqual(status(Env(info_formula=fi).formula(), "bottle_available"), "fail")

    def test_dry_run_touches_dependent(self):
        with open(fixture_path("brew/dryrun_aom.txt")) as f:
            r = Env(dry=f.read()).formula()
        self.assertEqual(status(r, "dry_run_only_target"), "fail")

    def test_post_install_new(self):
        e = Env(info_formula=formula_info(post_install_defined=True))
        e.keg("class Aom < Formula\nend\n")
        self.assertEqual(status(e.formula(), "post_install_unchanged"), "fail")

    def test_post_install_old_keg_missing_unknown(self):
        self.assertEqual(status(Env(info_formula=formula_info(post_install_defined=True)).formula(), "post_install_unchanged"), "unknown")

    def test_post_install_already_there(self):
        e = Env(info_formula=formula_info(post_install_defined=True))
        e.keg("class Aom < Formula\n  def post_install\n  end\nend\n")
        self.assertEqual(status(e.formula(), "post_install_unchanged"), "pass")

    def test_new_caveats(self):
        e = Env(info_formula=formula_info(caveats="run this"))
        e.keg("class Aom < Formula\nend\n")
        self.assertEqual(status(e.formula(), "caveats_unchanged"), "fail")

    def test_running_service(self):
        svc = json.dumps([{"name": "aom", "status": "started", "pid": 1}])
        self.assertEqual(status(Env(services=svc).formula(), "not_running_service"), "fail")

    def test_library_used_by_running_service(self):
        svc = json.dumps([{"name": "example-db", "status": "started", "pid": 77}])
        e = Env(services=svc)
        e.run.responses[("/usr/sbin/lsof", "-p", "77", "-Fn")] = cp("p77\nn%s/aom/3.15.2/lib/libaom.dylib\n" % e.cellar)
        r = e.formula()
        self.assertEqual(status(r, "not_running_service"), "fail")
        self.assertIn("example-db", next(c.detail for c in r.checks if c.name == "not_running_service"))

    def test_deprecated(self):
        self.assertEqual(status(Env(info_formula=formula_info(deprecated=True)).formula(), "not_deprecated"), "fail")

    def test_fresh_commit(self):
        self.assertEqual(status(Env(commit_hours=10).formula(), "cooldown"), "fail")
        self.assertEqual(status(Env(commit_hours=10).formula(accept_fresh=True), "cooldown"), "pass")

    def test_github_rate_limit_is_unknown(self):
        r = Env(commit_resp=Response(403, {}, b"")).formula()
        self.assertEqual(status(r, "cooldown"), "unknown")
        self.assertFalse(r.green)

    def test_candidate_below_fixed(self):
        self.assertEqual(status(Env().formula(fixed="4.0.0"), "candidate"), "fail")

    def test_brew_info_failure(self):
        e = Env()
        e.run.responses[(BREW, "info", "--json=v2", "--formula", "aom")] = cp("", 1)
        r = e.formula()
        self.assertFalse(r.green)
        self.assertEqual(r.checks[0].status, "error")


class CaskTest(unittest.TestCase):
    def test_green(self):
        r = Env().cask()
        self.assertTrue(r.green, [(c.name, c.status, c.detail) for c in r.checks])
        self.assertEqual([c.name for c in r.checks],
                         ["tap_cask", "candidate", "dry_run_only_target", "no_installer_scripts", "not_deprecated", "cooldown"])

    def test_app_path_evidence(self):
        self.assertEqual(Env().cask().evidence["app_path"], "/Applications/Blender.app")

    def test_pkg_installer_red(self):
        ci = Env.cask_info()
        ci["casks"][0]["artifacts"].append({"pkg": ["Installer.pkg"]})
        self.assertEqual(status(Env(info_cask=ci).cask(), "no_installer_scripts"), "fail")

    def test_postflight_red(self):
        ci = Env.cask_info()
        ci["casks"][0]["artifacts"].append({"postflight": None})
        self.assertEqual(status(Env(info_cask=ci).cask(), "no_installer_scripts"), "fail")


class LastChangeTest(unittest.TestCase):
    def test_rejects_bad_path(self):
        f = Fetcher(FakeTransport({}), ("api.github.com",))
        with self.assertRaises(ValueError):
            last_change(f, "Homebrew/homebrew-core", "../../etc/passwd")
        with self.assertRaises(ValueError):
            last_change(f, "evil/repo", "Formula/a/aom.rb")


if __name__ == "__main__":
    unittest.main()
