import getpass
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from tests.test_config import REPO_CONFIG
from vulnwatch import cli
from vulnwatch.store import RunLock, Store


def temp_config():
    tmp = tempfile.mkdtemp()
    with open(REPO_CONFIG) as f:
        data = json.load(f)
    data.update(user=getpass.getuser(), state_dir=os.path.join(tmp, "state"), log_dir=os.path.join(tmp, "logs"),
                aliases_file=os.path.join(os.path.dirname(REPO_CONFIG), "aliases.json"))
    path = os.path.join(tmp, "config.json")
    with open(path, "w") as f:
        json.dump(data, f)
    return path, data


class CliTest(unittest.TestCase):
    def test_run_already_running(self):
        path, data = temp_config()
        state = data["state_dir"] + "-dev"
        os.makedirs(state)
        out = io.StringIO()
        with RunLock(os.path.join(state, "run.lock")):
            with redirect_stdout(out):
                code = cli.main(["run", "--dev"], config_path=path)
        self.assertEqual(code, 4)
        self.assertIn("already running", out.getvalue())

    def test_ctx_wires_every_callable(self):
        path, data = temp_config()
        cfg = cli._config(True, path)
        ctx = cli._ctx(cfg, True, ["problema"], "/tmp/x", None, None, None)
        self.assertEqual(ctx.selfcheck(), ["problema"])
        self.assertTrue(callable(ctx.inventory))
        self.assertTrue(callable(ctx.notify))
        self.assertTrue(ctx.report_dir.endswith("reports"))
        self.assertTrue(ctx.actions_log.endswith("actions.jsonl"))
        self.assertIs(ctx.dev, True)

    def test_stale_lock_notifies(self):
        import time
        path, data = temp_config()
        state = data["state_dir"] + "-dev"
        os.makedirs(state)
        lock_path = os.path.join(state, "run.lock")
        notes = []
        with RunLock(lock_path):
            old = time.time() - 7 * 3600
            os.utime(lock_path, (old, old))
            with redirect_stdout(io.StringIO()):
                code = cli.main(["run", "--dev"], config_path=path, notifier=notes.append)
        self.assertEqual(code, 4)
        self.assertTrue(any("stuck" in n for n in notes), notes)

    def test_fresh_lock_does_not_notify(self):
        path, data = temp_config()
        state = data["state_dir"] + "-dev"
        os.makedirs(state)
        notes = []
        with RunLock(os.path.join(state, "run.lock")):
            with redirect_stdout(io.StringIO()):
                cli.main(["run", "--dev"], config_path=path, notifier=notes.append)
        self.assertEqual(notes, [])

    def test_config_error_notifies_on_run(self):
        bad = os.path.join(tempfile.mkdtemp(), "config.json")
        with open(bad, "w") as f:
            f.write("{non json")
        notes = []
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["run", "--dev"], config_path=bad, notifier=notes.append), 1)
        self.assertEqual(len(notes), 1)
        self.assertRegex(notes[0], r"^[0-9A-Za-zàèéìòù ,.:·-]*$")

    def test_apply_refuses_when_live_version_changed(self):
        from vulnwatch.model import Finding, InventoryItem, finding_id
        path, data = temp_config()
        prefix = tempfile.mkdtemp()
        pkg = os.path.join(prefix, "lib", "node_modules", "pnpm")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "package.json"), "w") as f:
            json.dump({"name": "pnpm", "version": "9.2.0"}, f)
        data["npm_global"]["prefix"] = prefix
        with open(path, "w") as f:
            json.dump(data, f)
        item = InventoryItem("npm_global", "pnpm", "9.0.0", "npm", "npm_global", prefix)
        fid = finding_id("CVE-2026-1000", item.kind, item.name, item.location)
        state = data["state_dir"] + "-dev"
        os.makedirs(state)
        s = Store(os.path.join(state, "state.db"))
        rid = s.start_run("2026-11-03T00:00:00Z")
        s.save_findings(rid, [Finding(fid, "CVE-2026-1000", item, "exact", True, False, False, "osv", "9.1.0", "t", None, "auto", ())], {})
        s.finish_run(rid, "ok", {})
        s.close()
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["apply", fid, "--dev"], config_path=path, notifier=lambda t: None), 1)
        self.assertIn("changed", out.getvalue())
        # apply logs its HTTP requests like run does (SECURITY.md I6), even when it stops early.
        from datetime import datetime, timezone
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.assertTrue(os.path.isfile(os.path.join(data["log_dir"] + "-dev", "requests-%s.log" % day)))

    def test_wrong_user_refused(self):
        path, data = temp_config()
        data["user"] = "qualcun-altro"
        with open(path, "w") as f:
            json.dump(data, f)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["run", "--dev"], config_path=path), 1)

    def test_ignore_records_reason(self):
        path, data = temp_config()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["ignore", "abc123", "--reason", "non usato", "--dev"], config_path=path), 0)
        s = Store(os.path.join(data["state_dir"] + "-dev", "state.db"))
        self.assertEqual(s.ignores(), {"abc123": "non usato"})

    def test_apply_unknown_id(self):
        path, data = temp_config()
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["apply", "nope", "--dev"], config_path=path), 1)
        self.assertIn("not found", out.getvalue())

    def test_report_without_reports(self):
        path, data = temp_config()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["report", "--dev"], config_path=path), 1)


if __name__ == "__main__":
    unittest.main()
