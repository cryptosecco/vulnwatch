import os
import tempfile
import unittest

from vulnwatch.selfcheck import MANIFEST_NAME, verify, write_manifest


class SelfcheckTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "vulnwatch"))
        for rel, body in (("vulnwatch.py", "print(1)\n"), ("vulnwatch/a.py", "x = 1\n"), ("config.json", "{}\n")):
            with open(os.path.join(self.root, rel), "w") as f:
                f.write(body)
        self.plist = os.path.join(tempfile.mkdtemp(), "x.plist")
        with open(self.plist, "w") as f:
            f.write("<plist/>")
        self.manifest = write_manifest(self.root)

    def check(self, **kw):
        return verify(self.root, self.plist, expect_uid=os.getuid(), **kw)

    def assertProblem(self, problems, word):
        self.assertTrue(any(word in p for p in problems), problems)

    def test_clean_tree(self):
        self.assertEqual(self.check(), [])
        self.assertTrue(os.path.exists(os.path.join(self.root, MANIFEST_NAME)))
        self.assertIn("vulnwatch/a.py", self.manifest)
        self.assertNotIn(MANIFEST_NAME, self.manifest)

    def test_modified_file(self):
        with open(os.path.join(self.root, "vulnwatch", "a.py"), "a") as f:
            f.write("evil()\n")
        self.assertProblem(self.check(), "hash")

    def test_extra_file(self):
        with open(os.path.join(self.root, "vulnwatch", "evil.py"), "w") as f:
            f.write("x")
        self.assertProblem(self.check(), "extra file")

    def test_missing_file(self):
        os.remove(os.path.join(self.root, "config.json"))
        self.assertProblem(self.check(), "missing file")

    def test_group_writable(self):
        os.chmod(os.path.join(self.root, "vulnwatch.py"), 0o664)
        self.assertProblem(self.check(), "writable")

    def test_symlink(self):
        os.symlink("/etc/hosts", os.path.join(self.root, "vulnwatch", "link.py"))
        self.assertProblem(self.check(), "symbolic link")

    def test_pycache(self):
        os.makedirs(os.path.join(self.root, "vulnwatch", "__pycache__"))
        self.assertProblem(self.check(), "bytecode")

    def test_wrong_owner(self):
        real = os.lstat

        class Fake:
            def __init__(self, st):
                self.st_mode, self.st_uid = st.st_mode, 501

        problems = verify(self.root, self.plist, expect_uid=0, stat=lambda p: Fake(real(p)))
        self.assertProblem(problems, "invalid owner")

    def test_plist_group_writable(self):
        os.chmod(self.plist, 0o664)
        self.assertProblem(self.check(), "plist")

    def test_plist_missing(self):
        os.remove(self.plist)
        self.assertProblem(self.check(), "plist")

    def test_manifest_unreadable(self):
        with open(os.path.join(self.root, MANIFEST_NAME), "w") as f:
            f.write("{not json")
        self.assertProblem(self.check(), "manifest")


if __name__ == "__main__":
    unittest.main()
