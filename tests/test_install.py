import getpass
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from vulnwatch.selfcheck import verify

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABEL = "local.vulnwatch"
PARTS = ("vulnwatch.py", "install.sh", "vulnwatch", "config", "launchd")


def make_repo():
    tmp = tempfile.mkdtemp()
    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)
    for p in PARTS:
        src = os.path.join(REPO, p)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(repo, p),
                            ignore=shutil.ignore_patterns("__pycache__", "config.json"))
        else:
            shutil.copy2(src, os.path.join(repo, p))
    with open(os.path.join(repo, ".gitignore"), "w") as f:
        f.write("config/config.json\n")
    with open(os.path.join(repo, "config", "config.example.json")) as f:
        local = json.load(f)
    local["user"] = getpass.getuser()
    with open(os.path.join(repo, "config", "config.json"), "w") as f:
        json.dump(local, f)
    git = ["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(git[:3] + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "x"], check=True)
    return tmp, repo


def head(repo):
    return subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()


def install(repo, root, home, *extra, sha=None):
    args = list(extra) if "--uninstall" in extra else list(extra) + [sha or head(repo)]
    return subprocess.run(["/bin/bash", os.path.join(repo, "install.sh"), "--test-root", root, "--test-user",
                           getpass.getuser(), "--test-home", home] + args,
                          capture_output=True, text=True, timeout=120)


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp, self.repo = make_repo()
        self.root = os.path.join(self.tmp, "root")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.root)
        os.makedirs(self.home)
        self.dest = os.path.join(self.root, "usr", "local", "libexec", "vulnwatch")
        self.plist = os.path.join(self.root, "Library", "LaunchAgents", LABEL + ".plist")
        self.wrapper = os.path.join(self.root, "usr", "local", "bin", "vulnwatch")

    def test_install_test_mode(self):
        r = install(self.repo, self.root, self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "vulnwatch.py")))
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "config", "config.json")))
        self.assertEqual(verify(self.dest, self.plist, expect_uid=os.getuid()), [])
        self.assertEqual(subprocess.run(["/usr/bin/plutil", "-lint", self.plist], capture_output=True).returncode, 0)
        with open(self.plist) as f:
            plist = f.read()
        self.assertIn("<integer>7</integer>", plist)
        self.assertIn("<integer>30</integer>", plist)
        self.assertIn("<string>-I</string>", plist)
        self.assertIn(self.home + "/Library/Logs/vulnwatch", plist)
        self.assertNotIn("@HOME@", plist)
        with open(self.wrapper) as f:
            self.assertIn("/usr/bin/python3 -I -B /usr/local/libexec/vulnwatch/vulnwatch.py", f.read())
        for dirpath, dirnames, _ in os.walk(self.dest):
            self.assertNotIn("__pycache__", dirnames)

    def test_refuses_dirty_repo(self):
        with open(os.path.join(self.repo, "untracked.txt"), "w") as f:
            f.write("x")
        r = install(self.repo, self.root, self.home)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not clean", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_update_replaces_and_uninstall_removes(self):
        self.assertEqual(install(self.repo, self.root, self.home).returncode, 0)
        self.assertEqual(install(self.repo, self.root, self.home).returncode, 0)
        self.assertFalse(os.path.exists(self.dest + ".old"))
        self.assertFalse(os.path.exists(self.dest + ".new"))
        r = install(self.repo, self.root, self.home, "--uninstall")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(self.plist))
        self.assertFalse(os.path.exists(self.wrapper))

    def test_requires_and_checks_the_reviewed_sha(self):
        r = subprocess.run(["/bin/bash", os.path.join(self.repo, "install.sh"), "--test-root", self.root, "--test-user",
                            getpass.getuser(), "--test-home", self.home], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        first = head(self.repo)
        with open(os.path.join(self.repo, "vulnwatch", "extra.py"), "w") as f:
            f.write("x = 1\n")
        git = ["git", "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run(git + ["add", "."], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "y"], check=True)
        r = install(self.repo, self.root, self.home, sha=first)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("HEAD", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_installs_committed_content_only(self):
        with open(os.path.join(self.repo, ".gitignore"), "a") as f:
            f.write(".claude/\n")
        git = ["git", "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run(git + ["add", ".gitignore"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "ignore"], check=True)
        os.makedirs(os.path.join(self.repo, "vulnwatch", ".claude"))
        with open(os.path.join(self.repo, "vulnwatch", ".claude", "evil.py"), "w") as f:
            f.write("evil = True\n")
        r = install(self.repo, self.root, self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.dest, "vulnwatch", ".claude")))

    def test_installs_local_config_and_refuses_without_it(self):
        r = install(self.repo, self.root, self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(os.path.join(self.dest, "config", "config.json")) as f:
            self.assertEqual(json.load(f)["user"], getpass.getuser())
        os.remove(os.path.join(self.repo, "config", "config.json"))
        r = install(self.repo, self.root, self.home)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("config.json", r.stdout + r.stderr)

    def test_version_file_written_and_in_manifest(self):
        r = install(self.repo, self.root, self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(os.path.join(self.dest, "VERSION")) as f:
            self.assertEqual(f.read(), head(self.repo) + "\n")
        with open(os.path.join(self.dest, "manifest.json")) as f:
            self.assertIn("VERSION", json.load(f))
        self.assertEqual(verify(self.dest, self.plist, expect_uid=os.getuid()), [])

    def test_missing_config_points_to_setup(self):
        os.remove(os.path.join(self.repo, "config", "config.json"))
        r = install(self.repo, self.root, self.home)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("./setup.sh", r.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_prints_next_steps(self):
        r = install(self.repo, self.root, self.home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("vulnwatch status", r.stdout)
        self.assertIn("2 hours", r.stdout)
        r = install(self.repo, self.root, self.home, "--no-first-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("vulnwatch run", r.stdout)

    def test_purge_removes_state_and_logs(self):
        state = os.path.join(self.home, "Library", "Application Support", "vulnwatch")
        logs = os.path.join(self.home, "Library", "Logs", "vulnwatch")
        self.assertEqual(install(self.repo, self.root, self.home).returncode, 0)
        for d in (state, logs):
            with open(os.path.join(d, "x"), "w") as f:
                f.write("x")
        r = install(self.repo, self.root, self.home, "--uninstall")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isdir(state) and os.path.isdir(logs))
        r = install(self.repo, self.root, self.home, "--uninstall", "--purge")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(state))
        self.assertFalse(os.path.exists(logs))
        self.assertTrue(os.path.isdir(os.path.join(self.home, "Library", "Logs")))

    def test_purge_requires_uninstall(self):
        r = install(self.repo, self.root, self.home, "--purge")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_home_with_spaces(self):
        home = os.path.join(self.tmp, "my home")
        os.makedirs(home)
        r = install(self.repo, self.root, home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(self.plist) as f:
            self.assertIn(home + "/Library/Logs/vulnwatch", f.read())
        self.assertEqual(subprocess.run(["/usr/bin/plutil", "-lint", self.plist], capture_output=True).returncode, 0)
        self.assertTrue(os.path.isdir(os.path.join(home, "Library", "Application Support", "vulnwatch")))

    def test_home_resolved_from_the_account_when_not_given(self):
        import pwd
        r = subprocess.run(["/bin/bash", os.path.join(self.repo, "install.sh"), "--test-root", self.root, "--test-user",
                            getpass.getuser(), head(self.repo), "--no-first-run"], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(self.plist) as f:
            self.assertIn(pwd.getpwnam(getpass.getuser()).pw_dir + "/Library/Logs/vulnwatch", f.read())

    def test_home_with_xml_and_sed_specials(self):
        home = os.path.join(self.tmp, "a&b|c<d e")
        os.makedirs(home)
        r = install(self.repo, self.root, home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(subprocess.run(["/usr/bin/plutil", "-lint", self.plist], capture_output=True).returncode, 0)
        with open(self.plist) as f:
            self.assertIn("a&amp;b|c&lt;d e/Library/Logs/vulnwatch", f.read())

    def test_relative_home_refused(self):
        r = install(self.repo, self.root, "relative/home")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("home", r.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_refuses_without_root_outside_test_mode(self):
        r = subprocess.run(["/bin/bash", os.path.join(self.repo, "install.sh")], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sudo", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
