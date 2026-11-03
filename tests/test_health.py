import os
import subprocess
import tempfile
import unittest

from vulnwatch.health import broken_venvs, path_node_version, services_on_old_keg
from vulnwatch.proc import FakeRunner


def cp(out="", code=0):
    return subprocess.CompletedProcess([], code, out, "")


class VenvTest(unittest.TestCase):
    def _venv(self, root, rel, home):
        d = os.path.join(root, rel)
        os.makedirs(d)
        with open(os.path.join(d, "pyvenv.cfg"), "w") as f:
            f.write("home = %s\ninclude-system-site-packages = false\n" % home)
        return d

    def test_broken_detected(self):
        root = tempfile.mkdtemp()
        bad = self._venv(root, "proj/.venv", "/nonexistent/python@3.14/bin")
        self._venv(root, "ok/.venv", "/usr/bin")
        self.assertEqual(broken_venvs([root]), [bad])

    def test_root_itself_is_venv(self):
        root = tempfile.mkdtemp()
        with open(os.path.join(root, "pyvenv.cfg"), "w") as f:
            f.write("home = /nonexistent\n")
        self.assertEqual(broken_venvs([root]), [root])

    def test_skips_node_modules_and_missing_roots(self):
        root = tempfile.mkdtemp()
        self._venv(root, "node_modules/x", "/nonexistent")
        self.assertEqual(broken_venvs([root, "/nonexistent/root"]), [])


class ServicesTest(unittest.TestCase):
    def test_service_on_old_keg(self):
        base = tempfile.mkdtemp()
        cellar = os.path.join(base, "Cellar")
        os.makedirs(os.path.join(cellar, "example-db", "15.17"))
        os.makedirs(os.path.join(base, "opt"))
        os.symlink(os.path.join(cellar, "example-db", "15.17"), os.path.join(base, "opt", "example-db"))
        lsof = "p123\nfcwd\nn/\nftxt\nn%s/example-db/15.16/bin/postgres\n" % cellar
        run = FakeRunner({("/usr/sbin/lsof", "-p", "123", "-Fn"): cp(lsof)})
        services = [{"name": "example-db", "status": "started", "pid": 123},
                    {"name": "other", "status": "stopped", "pid": None}]
        out = services_on_old_keg(run, cellar, services)
        self.assertEqual(len(out), 1)
        self.assertIn("example-db", out[0])
        self.assertIn("15.16", out[0])

    def test_service_on_current_keg_ok(self):
        base = tempfile.mkdtemp()
        cellar = os.path.join(base, "Cellar")
        os.makedirs(os.path.join(cellar, "pg", "2.0"))
        os.makedirs(os.path.join(base, "opt"))
        os.symlink(os.path.join(cellar, "pg", "2.0"), os.path.join(base, "opt", "pg"))
        run = FakeRunner({("/usr/sbin/lsof", "-p", "9", "-Fn"): cp("n%s/pg/2.0/bin/pg\n" % cellar)})
        self.assertEqual(services_on_old_keg(run, cellar, [{"name": "pg", "status": "started", "pid": 9}]), [])


class KegUsersTest(unittest.TestCase):
    def test_services_using_a_library_keg(self):
        from vulnwatch.health import keg_users
        cellar = "/opt/homebrew/Cellar"
        run = FakeRunner({("/usr/sbin/lsof", "-p", "5", "-Fn"): cp("n%s/openssl@3/3.5.9/lib/libssl.3.dylib\n" % cellar),
                          ("/usr/sbin/lsof", "-p", "6", "-Fn"): cp("n%s/example-cache/8.3.4/bin/mongod\n" % cellar)})
        services = [{"name": "pg", "status": "started", "pid": 5}, {"name": "mongo", "status": "started", "pid": 6}]
        self.assertEqual(keg_users(run, cellar, services, "openssl@3"), [("pg", "3.5.9")])


class NodeVersionTest(unittest.TestCase):
    def test_path_node_version(self):
        run = FakeRunner({("/x/node", "--version"): cp("v22.23.4\n")})
        self.assertEqual(path_node_version(run, "/x/node"), "22.23.4")
        self.assertIsNone(path_node_version(FakeRunner({}), "/x/node"))


if __name__ == "__main__":
    unittest.main()
