import dataclasses
import os
import subprocess
import tempfile
import types
import unittest

from tests.helpers import NOW
from vulnwatch import cli
from vulnwatch.apply import ApplyError, argv_for
from vulnwatch.config import load_config
from vulnwatch.health import path_node_version
from vulnwatch.inventory import collect
from vulnwatch.model import AuditResult, Finding, InventoryItem, finding_id
from vulnwatch.proc import FakeRunner
from vulnwatch.runner import make_audit, reinventory

REPO_CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.example.json")
SW_VERS = {("/usr/bin/sw_vers", "-productVersion"): subprocess.CompletedProcess([], 0, "27.0.1\n", "")}


def bare_cfg():
    return dataclasses.replace(load_config(REPO_CONFIG), brew=None, npm_global=None, path_node=None, app_dirs=(),
                               lockfile_roots=(), venv_roots=(), runtimes=())


def finding(item):
    return Finding(finding_id("CVE-2026-1", item.kind, item.name, item.location), "CVE-2026-1", item, "exact", True,
                   False, False, "osv", "9.9.9", "t", "2026-11-01", "manual", ())


BREW_ITEM = InventoryItem("brew_formula", "openssl@3", "3.0.0", None, "homebrew/core", "/opt/homebrew")
NPM_ITEM = InventoryItem("npm_global", "pnpm", "9.0.0", "npm", "npm_global", "/p")


class OptionalToolsTest(unittest.TestCase):
    def test_collect_without_brew_and_npm(self):
        items = collect(bare_cfg(), FakeRunner(SW_VERS), None)
        self.assertEqual([i.kind for i in items], ["macos"])

    def test_cli_inventory_does_not_call_brew(self):
        run = FakeRunner(SW_VERS)
        with tempfile.TemporaryDirectory() as d:
            ctx = cli._ctx(bare_cfg(), True, [], d, None, run, None)
            items = ctx.inventory()
        self.assertEqual([i.kind for i in items], ["macos"])
        self.assertFalse(any("brew" in " ".join(argv) for argv, _ in run.calls), run.calls)

    def test_argv_for_brew_without_brew_raises(self):
        audit = AuditResult("x", "3.0.1", [], {})
        with self.assertRaisesRegex(ApplyError, "Homebrew"):
            argv_for(finding(BREW_ITEM), audit, bare_cfg(), NOW)

    def test_argv_for_npm_without_npm_raises(self):
        audit = AuditResult("x", "9.0.1", [], {})
        with self.assertRaisesRegex(ApplyError, "npm"):
            argv_for(finding(NPM_ITEM), audit, bare_cfg(), NOW)

    def test_make_audit_npm_without_npm_global_is_none(self):
        run = FakeRunner({})
        ctx = types.SimpleNamespace(cfg=bare_cfg(), run=run)
        self.assertIsNone(make_audit(ctx, finding(NPM_ITEM), None, set()))
        self.assertEqual(run.calls, [])

    def test_reinventory_npm_without_npm_global_is_none(self):
        ctx = types.SimpleNamespace(cfg=bare_cfg(), run=FakeRunner({}))
        self.assertIsNone(reinventory(ctx, NPM_ITEM))

    def test_path_node_none_runs_nothing(self):
        run = FakeRunner({})
        self.assertIsNone(path_node_version(run, None))
        self.assertEqual(run.calls, [])

    def test_chrome_manual_check_name_is_english(self):
        chrome = InventoryItem("app", "com.google.Chrome", "156.0", None, "google_updater", "/Applications/Google Chrome.app")
        ctx = types.SimpleNamespace(cfg=bare_cfg(), run=FakeRunner({}))
        audit = make_audit(ctx, finding(chrome), None, set(), interactive=True)()
        self.assertEqual([c.name for c in audit.checks], ["manual_approval"])


if __name__ == "__main__":
    unittest.main()


class BrewNullReviewFixTest(unittest.TestCase):
    def test_brew_client_without_brew_raises_value_error(self):
        from vulnwatch.brew_client import BrewClient
        run = FakeRunner({})
        client = BrewClient(run, None)
        for call in (client.cellar, client.services, client.update, lambda: client.info("x")):
            with self.assertRaisesRegex(ValueError, "Homebrew"):
                call()
        self.assertEqual(run.calls, [])

    def test_apply_context_without_brew(self):
        # The real Runner: with brew=None the argv holds None, which subprocess rejects with TypeError.
        from vulnwatch.proc import Runner
        from vulnwatch.runner import apply_context
        with tempfile.TemporaryDirectory() as d:
            ctx = cli._ctx(bare_cfg(), False, [], d, None, Runner(), None)
            actx = apply_context(ctx, "9.0.1")
            with self.assertRaises(ValueError):
                actx.services()
        self.assertTrue(actx.cellar)
