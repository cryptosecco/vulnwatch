import os
import shutil
import tempfile
import unittest

from tests.helpers import fixture_path
from vulnwatch.inventory import lockfiles as lf


def text(name):
    with open(fixture_path("lockfiles/" + name)) as f:
        return f.read()


class ParserTest(unittest.TestCase):
    def test_package_lock_v3(self):
        self.assertEqual(lf.parse_package_lock(text("package-lock-v3.json")),
                         [("lodash", "4.17.20"), ("@scope/pkg", "1.2.3"), ("lodash", "4.17.21")])

    def test_package_lock_v1(self):
        self.assertEqual(lf.parse_package_lock(text("package-lock-v1.json")),
                         [("lodash", "4.17.20"), ("minimist", "1.2.5")])

    def test_pnpm(self):
        self.assertEqual(lf.parse_pnpm_lock(text("pnpm-lock.yaml")),
                         [("@scope/pkg", "1.2.3"), ("lodash", "4.17.20"), ("react-dom", "18.2.0")])

    def test_yarn_classic(self):
        self.assertEqual(lf.parse_yarn_lock(text("yarn-classic.lock")),
                         [("@scope/pkg", "1.2.3"), ("lodash", "4.17.20")])

    def test_yarn_berry(self):
        self.assertEqual(lf.parse_yarn_lock(text("yarn-berry.lock")),
                         [("lodash", "4.17.20"), ("@scope/pkg", "1.2.3")])

    def test_bun(self):
        self.assertEqual(lf.parse_bun_lock(text("bun.lock")),
                         [("lodash", "4.17.20"), ("@scope/pkg", "1.2.3")])

    def test_requirements(self):
        self.assertEqual(lf.parse_requirements(text("requirements.txt")),
                         [("django", "4.2.1"), ("flask-login", "0.6.2")])

    def test_garbage_does_not_raise(self):
        self.assertEqual(lf.parse_package_lock("{not json"), [])
        self.assertEqual(lf.parse_bun_lock("garbage"), [])


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def put(self, rel, src="package-lock-v3.json"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy(fixture_path("lockfiles/" + src), path)
        return path

    def locations(self, items):
        return sorted({os.path.relpath(i.location, self.root) for i in items})

    def test_finds_and_skips(self):
        self.put("proj/package-lock.json")
        self.put("proj/node_modules/x/package-lock.json")
        self.put("a/b/c/d/package-lock.json")
        self.put("a/b/c/d/e/package-lock.json")
        self.put("py/requirements.txt", "requirements.txt")
        items = lf.scan([self.root], 4, [])
        self.assertEqual(self.locations(items),
                         ["a/b/c/d/package-lock.json", "proj/package-lock.json", "py/requirements.txt"])
        it = next(i for i in items if i.name == "django")
        self.assertEqual((it.kind, it.ecosystem, it.version), ("lockfile_pkg", "PyPI", "4.2.1"))
        self.assertTrue(all(i.ecosystem == "npm" for i in items if i.location.endswith("package-lock.json")))

    def test_dedup_per_file(self):
        self.put("proj/pnpm-lock.yaml", "pnpm-lock.yaml")
        items = lf.scan([self.root], 4, [])
        self.assertEqual(sorted(i.name for i in items), ["@scope/pkg", "lodash", "react-dom"])

    def test_symlinked_dir_not_followed(self):
        other = tempfile.mkdtemp()
        os.makedirs(os.path.join(other, "proj"))
        shutil.copy(fixture_path("lockfiles/package-lock-v3.json"), os.path.join(other, "proj", "package-lock.json"))
        os.symlink(os.path.join(other, "proj"), os.path.join(self.root, "link"))
        self.assertEqual(lf.scan([self.root], 4, []), [])

    def test_protected_never_read(self):
        self.put("Documents/proj/package-lock.json")
        self.put("Code/proj/package-lock.json")
        items = lf.scan([self.root], 4, [os.path.join(self.root, "Documents")])
        self.assertEqual(self.locations(items), ["Code/proj/package-lock.json"])

    def test_missing_root_ignored(self):
        self.assertEqual(lf.scan(["/nonexistent/root"], 4, []), [])


if __name__ == "__main__":
    unittest.main()
