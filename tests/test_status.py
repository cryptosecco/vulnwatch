import dataclasses
import os
import subprocess
import tempfile
import unittest

from vulnwatch.config import load_config
from vulnwatch.i18n import set_language
from vulnwatch.proc import FakeRunner
from vulnwatch.status import status_lines
from vulnwatch.store import Store

REPO_CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.example.json")
LOADED = ("/bin/launchctl", "print", "gui/501/local.vulnwatch")


class StatusTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        d = self._tmp.name
        self.install_root = os.path.join(d, "libexec")
        self.plist = os.path.join(d, "local.vulnwatch.plist")
        self.cfg = dataclasses.replace(load_config(REPO_CONFIG), state_dir=os.path.join(d, "state"),
                                       log_dir=os.path.join(d, "logs"))
        os.makedirs(os.path.join(self.cfg.state_dir, "reports"))
        self.store = Store(os.path.join(self.cfg.state_dir, "state.db"))

    def tearDown(self):
        self.store.close()
        set_language("en")
        self._tmp.cleanup()

    def lines(self, run=None, verify_fn=lambda root, plist: []):
        return "\n".join(status_lines(self.cfg, self.install_root, self.plist, run or FakeRunner({}), 501, self.store,
                                      verify_fn=verify_fn))

    def test_status_not_installed(self):
        out = self.lines()
        self.assertIn("not installed", out)
        self.assertIn("not loaded", out)
        self.assertIn("no runs yet", out)
        self.assertIn("about 2 hours", out)
        self.assertIn("shadow", out)

    def test_status_after_run(self):
        os.makedirs(self.install_root)
        with open(os.path.join(self.install_root, "VERSION"), "w") as f:
            f.write("0123456789abcdef0123456789abcdef01234567\n")
        rid = self.store.start_run("2026-11-03T06:30:00Z")
        self.store.finish_run(rid, "ok", {})
        report = os.path.join(self.cfg.state_dir, "reports", "2026-11-03.md")
        with open(report, "w") as f:
            f.write("# vulnwatch · 2026-11-03\n\nAutomatic lane: off.\nSummary per item: 0 malicious · 2 waiting for you.\n")
        run = FakeRunner({LOADED: subprocess.CompletedProcess([], 0, "", "")})
        out = self.lines(run=run)
        self.assertIn("0123456789ab", out)
        self.assertIn("intact", out)
        self.assertIn("07:30", out)
        self.assertIn("ok", out)
        self.assertIn(report, out)
        self.assertIn("2 waiting for you", out)
        self.assertNotIn("about 2 hours", out)

    def test_status_reports_tampering(self):
        os.makedirs(self.install_root)
        out = self.lines(verify_fn=lambda root, plist: ["manifest missing"])
        self.assertIn("vulnwatch selfcheck", out)

    def test_status_first_run_in_progress(self):
        self.store.start_run("2026-11-03T06:30:00Z")
        self.store.queue("cverecord", "CVE-2026-1")
        out = self.lines()
        self.assertIn("in progress", out)
        self.assertIn("about 2 hours", out)
        self.assertIn("1", out)

    def test_status_italian(self):
        set_language("it")
        out = self.lines()
        self.assertIn("non installato", out)
        self.assertIn("ombra", out)

    def test_status_finds_italian_summary_line(self):
        with open(os.path.join(self.cfg.state_dir, "reports", "2026-11-03.md"), "w") as f:
            f.write("# vulnwatch\n\nRiepilogo per elemento: 3 da approvare.\n")
        self.assertIn("3 da approvare", self.lines())


class StoreRunsTest(unittest.TestCase):
    def test_store_last_run_and_pending(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(os.path.join(d, "state.db"))
            try:
                self.assertIsNone(s.last_run())
                self.assertEqual(s.pending_count(), 0)
                self.assertFalse(s.has_completed_run())
                rid = s.start_run("2026-11-03T06:30:00Z")
                self.assertEqual(s.last_run()["started_at"], "2026-11-03T06:30:00Z")
                self.assertIsNone(s.last_run()["finished_at"])
                s.finish_run(rid, "partial", {})
                self.assertEqual(s.last_run()["status"], "partial")
                self.assertTrue(s.has_completed_run())
                s.queue("cverecord", "CVE-2026-1")
                s.queue("cverecord", "CVE-2026-2")
                self.assertEqual(s.pending_count(), 2)
            finally:
                s.close()


if __name__ == "__main__":
    unittest.main()


class CliStatusTest(unittest.TestCase):
    def test_cli_status_is_read_only(self):
        import getpass
        import json
        from unittest import mock
        from vulnwatch import cli
        with tempfile.TemporaryDirectory() as d:
            with open(REPO_CONFIG) as f:
                data = json.load(f)
            data.update(user=getpass.getuser(), state_dir=os.path.join(d, "state"), log_dir=os.path.join(d, "logs"))
            p = os.path.join(d, "config.json")
            with open(p, "w") as f:
                json.dump(data, f)
            printed = []
            with mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(map(str, a)))):
                self.assertEqual(cli.main(["status"], config_path=p), 0)
            self.assertTrue(any(line.startswith("Mode:") for line in printed), printed)
            self.assertFalse(os.path.exists(os.path.join(d, "state")))
            self.assertFalse(os.path.exists(os.path.join(d, "logs")))
